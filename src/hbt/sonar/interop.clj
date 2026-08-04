(ns hbt.sonar.interop
  "Security rules for the Java libraries Clojure calls.

  The premise: Clojure runs on the JDK and reaches for the same
  `MessageDigest`, `Cipher`, `SSLContext`, `DocumentBuilderFactory` and
  `ObjectInputStream` as Java does, so it inherits the same CVE classes.
  Sonar's Java analyzer cannot see any of it -- it parses Java source, and
  measured against this server its 720 rules share no repository with Scala's
  41 or Kotlin's 145. Each JVM language pays for its own.

  What it does NOT try to reproduce: the Java rules about Java's syntax --
  null dereference, equals/hashCode, try-with-resources, mutable statics.
  Those are meaningless here. Nor most of Java's concurrency rules, since
  Clojure's defaults are immutable; the concurrency hazards Clojure DOES have
  are its own, and live in hbt.sonar.concurrency.

  Class names are resolved through the ns form's :import, so both
  `(MessageDigest/getInstance ...)` and
  `(java.security.MessageDigest/getInstance ...)` match the same rule."
  (:require [clojure.string :as str]
            [hbt.sonar.tree :as tree]))

;; ---------------------------------------------------------------------------
;; Import resolution.

(defn imports
  "simple class name -> fully qualified, from the ns form's :import clauses.
  Handles both `[java.security MessageDigest Signature]` and a bare
  `java.util.Random`."
  [nodes]
  (let [import-forms (tree/lists-headed-by nodes #{":import"})]
    (reduce
     (fn [acc form]
       (let [kids (remove #(= :trivia (:type %)) (tree/children-of nodes form))]
         (reduce
          (fn [a n]
            (cond
              ;; [package Class Class]
              (= :vector (:tag n))
              (let [syms (->> (tree/children-of nodes n)
                              (filter #(= :symbol (:type %)))
                              (map :text))]
                (if-let [pkg (first syms)]
                  (reduce (fn [m c] (assoc m c (str pkg "." c))) a (rest syms))
                  a))

              ;; bare java.util.Random
              (and (= :symbol (:type n)) (str/includes? (:text n) "."))
              (assoc a (last (str/split (:text n) #"\.")) (:text n))

              :else a))
          acc kids)))
     {} import-forms)))

(defn- resolve-class
  "A class name as written -> fully qualified, if we can tell."
  [imported nm]
  (cond
    (nil? nm) nil
    (str/includes? nm ".") nm
    :else (get imported nm)))

;; ---------------------------------------------------------------------------
;; The rule table. Each entry is data: a class, a member, and optionally a
;; predicate over the first string argument.

(def detections
  "Class, member, and optionally a predicate over the first string argument.
  Nothing else: title, severity, CWE and prose live in
  org/sonar/l10n/clj/rules/clj-kondo/<key>.{json,html}.

  This table STAYS in code, unlike the metadata. The argument predicates are
  regular expressions -- programs, not content -- and moving them to JSON
  would mean either losing reader-syntax validation or inventing a matcher
  DSL to put it back. The metadata moved because a title, a severity and a
  CWE are content: reviewable by someone who does not write Clojure, and
  translatable. A class/member/regex triple is neither.

  Consistency would argue both belong in resources. That is the Occam
  reading. These are two concerns that happen to sit near each other -- WHAT
  to detect, and HOW to describe it -- and they are already correctly
  separated."
  [{:key "weak-hash-algorithm" :class "java.security.MessageDigest" :member "getInstance"
    :arg #"(?i)^(MD5|SHA-?1|MD2|MD4)$"}
   {:key "cipher-ecb-mode" :class "javax.crypto.Cipher" :member "getInstance"
    :arg #"(?i)/ECB/"}
   {:key "weak-cipher-algorithm" :class "javax.crypto.Cipher" :member "getInstance"
    :arg #"(?i)^(DES|DESede|RC2|RC4|Blowfish)(/|$)"}
   {:key "weak-tls-protocol" :class "javax.net.ssl.SSLContext" :member "getInstance"
    :arg #"(?i)^(SSL|SSLv2|SSLv3|TLSv1|TLSv1\.1)$"}
   {:key "insecure-random" :class "java.util.Random" :member :new}
   {:key "unsafe-deserialization" :class "java.io.ObjectInputStream" :member :new}
   {:key "unsafe-deserialization" :class "java.beans.XMLDecoder" :member :new}
   {:key "jndi-injection" :class "javax.naming.InitialContext" :member "doLookup" :dynamic true}
   {:key "jndi-injection" :class "javax.naming.Context" :member "lookup" :dynamic true}
   {:key "predictable-temp-file" :class "java.io.File" :member "createTempFile"}
   {:key "xml-external-entity" :class "javax.xml.parsers.DocumentBuilderFactory" :member "newInstance"}
   {:key "xml-external-entity" :class "javax.xml.parsers.SAXParserFactory" :member "newInstance"}
   {:key "xml-external-entity" :class "javax.xml.transform.TransformerFactory" :member "newInstance"}
   {:key "xml-external-entity" :class "javax.xml.stream.XMLInputFactory" :member "newInstance"}
   {:key "shell-invocation" :class "java.lang.ProcessBuilder" :member :new}])

(def rule-keys
  "Every rule this namespace can raise, including the shape-matched one."
  (vec (distinct (conj (mapv :key detections) "trust-all-certificates"))))

(def ^:private by-target
  (reduce (fn [m r] (update m [(:class r) (:member r)] (fnil conj []) r)) {} detections))

(def ^:private hardening-calls
  "Setter -> the literal that means \"locked down\". Checked as CALLS with
  their argument, never as text in the enclosing form: the previous version
  regex-matched the form's raw source, so a `;; TODO disallow-doctype-decl`
  comment silenced the rule, and so did setting the very same feature to
  false. A comment must never disable a security finding."
  {".setXIncludeAware"          "false"
   ".setExpandEntityReferences" "false"})

(def ^:private hardening-features
  "Feature URI fragment -> the value that hardens it."
  {"disallow-doctype-decl"        "true"
   "FEATURE_SECURE_PROCESSING"    "true"
   "external-general-entities"    "false"
   "external-parameter-entities"  "false"
   "load-external-dtd"            "false"
   "ACCESS_EXTERNAL_DTD"          ""
   "ACCESS_EXTERNAL_STYLESHEET"   ""
   "SUPPORT_DTD"                  "false"})

(defn- enclosing-top-level [nodes n]
  (->> nodes
       (filter #(and (= :list (:tag %))
                     (<= (:line %) (:line n))
                     (>= (:end-line %) (:end-line n))))
       (sort-by :depth)
       first))

(defn- hardening-call?
  "True when this call is a parser lock-down with the right polarity."
  [nodes n]
  (when (= :list (:tag n))
    (let [args (tree/arguments nodes n)
          head (:head n)]
      (cond
        (contains? hardening-calls head)
        (= (get hardening-calls head) (:text (last args)))

        (contains? #{".setFeature" ".setProperty" ".setAttribute"} head)
        (let [[k v] (take-last 2 args)
              key-text (or (tree/unquote-string k) (:text k) "")]
          (boolean (some (fn [[frag want]]
                           (and (str/includes? key-text frag)
                                (or (= want "") (= want (:text v)))))
                         hardening-features)))

        :else false))))

(defn- hardened?
  "True when the enclosing form contains a real hardening CALL."
  [nodes n]
  (when-let [form (enclosing-top-level nodes n)]
    (boolean (some #(hardening-call? nodes %) (tree/children-of nodes form)))))

(defn- matches? [nodes lst {:keys [arg dynamic]}]
  (and (if dynamic
         ;; the weakness needs a name the caller can influence; a compile-time
         ;; constant lookup is not it
         (let [a (tree/first-argument nodes lst)] (and a (not (tree/literal? a))))
         true)
       (or (nil? arg)
           (when-let [s (tree/unquote-string (tree/first-argument nodes lst))]
             (boolean (re-find arg s))))))

(def ^:private trust-types
  #{"X509TrustManager" "TrustManager" "X509ExtendedTrustManager" "HostnameVerifier"
    "javax.net.ssl.X509TrustManager" "javax.net.ssl.TrustManager"
    "javax.net.ssl.X509ExtendedTrustManager" "javax.net.ssl.HostnameVerifier"})

(defn- trust-all-findings
  "A reify/proxy of a TrustManager or HostnameVerifier. There is no safe
  reason to implement these by hand in application code: the JDK's default
  already does the checking, and overriding it exists to switch it off."
  [nodes]
  (for [n (tree/lists-headed-by nodes #{"reify" "proxy"})
        :when (some #(and (= :symbol (:type %)) (contains? trust-types (:text %)))
                    (tree/children-of nodes n))]
    {:rule "trust-all-certificates"
     :line (:line n) :col (:col n) :end-line (:end-line n) :end-col (:end-col n)
     :message "hand-written TrustManager/HostnameVerifier -- confirm it does not accept every certificate"}))

(defn findings
  "Java-interop security findings for one parsed file."
  [nodes]
  (let [imported (imports nodes)]
    (for [n nodes
          :when (and (= :list (:tag n)) (not (:commented? n)) (:head n))
          :let [[cls member] (tree/head-parts (:head n))
                fq (resolve-class imported cls)]
          :when fq
          r (distinct (concat (get by-target [fq member])
                              (when-not (= :new member) (get by-target [fq :new]))))
          :when (and (or (= (:member r) member)
                         (and (= :new (:member r)) (= :new member)))
                     (matches? nodes n r)
                     ;; a parser that IS hardened is not a finding
                     (not (and (= "xml-external-entity" (:key r))
                               (hardened? nodes n))))]
      {:rule (:key r)
       :line (:line n) :col (:col n)
       :end-line (:end-line n) :end-col (:end-col n)
       :message (str fq (when (string? member) (str "/" member))
                     (if (= "xml-external-entity" (:key r))
                       " -- confirm external entity resolution is disabled"
                       " -- see the rule description"))})))

(def ^:private clojure-rng
  "clojure.core's RNG, all of which delegate to java.util.Random. Missing
  these made the rule blind to the idiomatic Clojure token-generation bug --
  `(apply str (repeatedly 32 #(rand-nth alphabet)))` produced nothing."
  #{"rand" "rand-int" "rand-nth" "shuffle" "Math/random" "clojure.core/rand"
    "clojure.core/rand-int" "clojure.core/rand-nth" "clojure.core/shuffle"})

(defn- clojure-rng-findings [nodes]
  (for [n (tree/lists-headed-by nodes clojure-rng)]
    {:rule "insecure-random"
     :line (:line n) :col (:col n) :end-line (:end-line n) :end-col (:end-col n)
     :message (str (:head n) " delegates to java.util.Random -- confirm nothing an"
                   " attacker must not guess is derived from it")}))

(defn all-findings [nodes]
  (concat (findings nodes) (trust-all-findings nodes) (clojure-rng-findings nodes)))
