(ns hbt.sonar.web
  "Rules for the Clojure web stack -- hiccup, ring, reitit.

  This is the bucket Java fills with 103 Spring and JavaEE rules. The
  framework differs; the vulnerability classes do not. XSS (CWE-79), CSRF
  (CWE-352) and credential exposure (CWE-200, CWE-522) were the largest
  remaining gaps against Java's coverage, and all three live in framework
  usage rather than in the language.

  No generic analyzer ships these for Clojure, because they require knowing
  what hiccup's escaping guarantees are and where ring's middleware sits."
  (:require [clojure.string :as str]
            [hbt.sonar.tree :as tree]))

(def rule-keys ["xss-unescaped-output" "csrf-protection-absent"
                "sensitive-data-logged" "cookie-missing-security-flags"])

(def ^:private raw-html
  "Ways to put a string into a page without hiccup escaping it. Each exists
  precisely to bypass the escaping, which is why each needs a reason."
  #{"raw" "h/raw" "hiccup.util/raw-string" "raw-string" "hiccup.core/raw"
    "hiccup2.core/raw" "util/raw-string"})

(def ^:private state-changing #{":post" ":put" ":patch" ":delete" "POST" "PUT" "PATCH" "DELETE"})

(def ^:private logging
  #{"log/info" "log/warn" "log/error" "log/debug" "log/trace" "println" "prn"
    "timbre/info" "timbre/warn" "timbre/error" "timbre/debug" "tap>"})

(def ^:private secret-name
  #"(?i)(^|[-_*/.])(passwords?|passwds?|secrets?|api[-_]?keys?|tokens?|credentials?|private[-_]?keys?|access[-_]?keys?|client[-_]?secrets?|session[-_]?ids?|jwts?)([-_*?!]|$)")

(defn- text-of [nodes n]
  (str/join " " (map :text (tree/children-of nodes n))))

(defn findings [nodes]
  (concat
   ;; hiccup escapes strings it renders; `raw` is the documented way to opt
   ;; out. A raw call whose argument is not a literal is rendering something
   ;; computed, unescaped.
   (for [l (tree/lists-headed-by nodes raw-html)
         :let [a (tree/first-argument nodes l)]
         :when (and a (not (tree/literal? a)))]
     {:rule "xss-unescaped-output"
      :line (:line l) :col (:col l) :end-line (:end-line l) :end-col (:end-col l)
      :message (str (:head l) " renders a computed value without escaping it")})

   ;; A namespace that routes state-changing methods and never mentions
   ;; anti-forgery. File-scoped on purpose: middleware is usually assembled
   ;; somewhere other than the route it protects, so this is a hotspot.
   (let [all (str/join " " (map :text (filter #(= :keyword (:type %)) nodes)))
         methods (some #(str/includes? all %) state-changing)
         guarded (some (fn [n] (and (= :symbol (:type n))
                                    (re-find #"(?i)anti-forgery|csrf" (:text n))))
                       nodes)]
     (when (and methods (not guarded))
       (for [n (take 1 (filter #(and (= :keyword (:type %))
                                     (contains? state-changing (:text %))) nodes))]
         {:rule "csrf-protection-absent"
          :line (:line n) :col (:col n) :end-line (:end-line n) :end-col (:end-col n)
          :message "state-changing routes here, and no anti-forgery middleware named in this namespace"})))

   ;; A credential-shaped name handed to a logger. Logs are copied, shipped
   ;; and retained far more widely than the store the secret came from.
   (for [l (tree/lists-headed-by nodes logging)
         :let [args (tree/arguments nodes l)]
         a args
         :when (and (= :symbol (:type a)) (re-find secret-name (:text a)))]
     {:rule "sensitive-data-logged"
      :line (:line a) :col (:col a) :end-line (:end-line a) :end-col (:end-col a)
      :message (str "'" (:text a) "' is credential-shaped and is being logged")})

   ;; A cookie map that sets one security flag has clearly thought about
   ;; them; one that turns a flag off, or omits :http-only while setting
   ;; others, has usually not.
   (for [n nodes
         :when (and (= :map (:tag n)) (not (:commented? n)))
         :let [t (text-of nodes n)]
         :when (and (re-find #":secure|:http-only|:same-site" t)
                    (or (re-find #":secure\s+false" t)
                        (re-find #":http-only\s+false" t)
                        (not (str/includes? t ":http-only"))))]
     {:rule "cookie-missing-security-flags"
      :line (:line n) :col (:col n) :end-line (:end-line n) :end-col (:end-col n)
      :message "cookie attributes set without :http-only true, or with a flag disabled"})))
