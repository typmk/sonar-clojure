(ns hbt.sonar.security
  "Security rules that have no call to hang a clj-kondo hook on.

  The call-shaped rules -- eval, read-string, sh, jdbc, MessageDigest and the
  rest -- moved to clj-kondo/hbt/security.clj, where they key on the RESOLVED
  var instead of matching a name as text. What remains here is shape-based: a
  def whose NAME looks like a credential, a permission mode written as a
  string literal, a shell call with only literal arguments.

  The sink and source sets survive for one reason: seeding the interprocedural
  pass in hbt.sonar.callgraph, which needs to know which vars reach a sink even
  though the direct finding is now raised by a hook."
  (:require [hbt.sonar.parse :as parse]
            [hbt.sonar.tree :as tree]))

(def ^:private sources
  "Forms whose result is attacker-influenced. Deliberately small: a false
  source produces a false flow, and a security rule nobody trusts is worse
  than no rule."
  #{"slurp" "read-line" "System/getenv" "System/getProperty"
    ".getParameter" ".getHeader" ".getQueryString" ".getInputStream"
    ":params" ":query-params" ":form-params" ":body" ":json-params" ":headers"
    ":query-string" ":path-params" ":multipart-params"})

(def ^:private eval-fns        #{"eval" "load-string" "load-reader"})
(def ^:private read-string-fns #{"read-string" "clojure.core/read-string"})
(def ^:private shell-fns       #{"sh" "clojure.java.shell/sh" ".exec" "shell"})
(def ^:private sql-fns         #{"query" "execute!" "jdbc/query" "jdbc/execute!"
                                 "sql/query" "db/query" "execute-one!"})
(def ^:private build-fns       #{"str" "format" "clojure.core/str" "clojure.core/format"})
(def ^:private xml-fns         #{"clojure.data.xml/parse" "xml/parse" "parse-str" "xml/parse-str"})

(def ^:private credential-name
  "Anchored on segment boundaries. Unanchored, `bypass` matches `pass` and
  `tokenizer` matches `token` -- and a security rule that cries wolf is a
  security rule nobody reads."
  #"(?i)(^|[-_*/.])(passwords?|passwds?|secrets?|api[-_]?keys?|tokens?|credentials?|private[-_]?keys?|access[-_]?keys?|client[-_]?secrets?)([-_*?!]|$)")

(defn- finding [rule node message]
  {:rule rule
   :line (:line node) :col (:col node)
   :end-line (:end-line node) :end-col (:end-col node)
   :message message})

(defn- dynamic-arg? [nodes lst]
  (let [a (tree/first-argument nodes lst)]
    (and a (not (tree/literal? a)))))

(defn- any-dynamic-arg?
  "True when ANY argument is computed. A shell call is dangerous because of
  the argument that carries the payload, which is rarely the first one."
  [nodes lst]
  (->> (tree/children-of nodes lst)
       (remove #(= :trivia (:type %)))
       (remove #(= (:head lst) (:text %)))
       (filter #(contains? #{:symbol :list} (if (= :list (:tag %)) :list (:type %))))
       (some #(not (tree/literal? %)))
       boolean))

(defn- world-accessible?
  "The others digit carries a bit. The previous pattern required a LEADING 7,
  so \"0700\" (owner-only) fired and \"0666\" did not."
  [s]
  (boolean
   (and s
        (or (and (re-matches #"0?[0-7]{3}" s)
                 (pos? (bit-and (parse-long (str (last s))) 2r011)))
            (re-matches #"[-dlbcps][-r][-w][-xsS][-r][-w][-xsS][-r][-w][-xtT]" s)
            (re-matches #"[-r][-w][-xsS][-r][-w][-xsS][-r][-w][-xtT]" s)))))

(defn findings
  "Shape-based security findings for one parsed file."
  [nodes]
  (concat
   (for [l (tree/lists-headed-by nodes shell-fns)
         :when (not (any-dynamic-arg? nodes l))]
     (finding "shell-invocation" l
              "shell invocation -- confirm no argument is caller-controlled"))

   ;; The def's VALUE, not its docstring.
   (for [l (tree/lists-headed-by nodes #{"def" "defonce"})
         :let [args (tree/arguments nodes l)
               nm   (first args)
               v    (let [lst (last args)]
                      (when (and (= :string (:type lst))
                                 (or (= 2 (count args))
                                     (not= lst (second args))))
                        lst))]
         :when (and nm v (re-find credential-name (:text nm))
                    (> (count (:text v)) 6))]
     (finding "hardcoded-credential" v
              (str "credential-shaped name '" (:text nm) "' is bound to a literal")))

   (for [l (tree/lists-headed-by nodes xml-fns)]
     (finding "xml-external-entity" l
              "confirm this parser has external entity resolution disabled"))

   (for [n nodes
         :when (and (= :string (:type n)) (not (:commented? n)))
         :let [s (tree/unquote-string n)]
         :when (world-accessible? s)]
     (finding "permissive-file-permissions" n
              (str "mode " s " grants access to others")))))

(defn- namespace-name [nodes]
  (when-let [nsform (first (tree/lists-headed-by nodes #{"ns"}))]
    (:text (tree/first-argument nodes nsform))))

(defn- enclosing-var
  "The name of the innermost defn/def enclosing `n`, by position."
  [nodes n]
  (->> (tree/lists-headed-by nodes #{"defn" "defn-" "def" "defmacro" "defmethod"})
       (filter #(and (<= (:line %) (:line n)) (>= (:end-line %) (:line n))))
       (sort-by #(- (:end-line %) (:line %)))
       first
       (#(when % (tree/first-argument nodes %)))
       :text))

(defn- dangerous-sinks
  "Sink calls that are actually unsafe, not merely sinks.

  Seeding from raw function NAMES was wrong: it flagged a correctly
  parameterised `jdbc/execute!` because the name matched, and produced six
  false interprocedural paths in lume."
  [nodes]
  (concat
   (filter #(dynamic-arg? nodes %) (tree/lists-headed-by nodes eval-fns))
   (tree/lists-headed-by nodes read-string-fns)
   (filter #(any-dynamic-arg? nodes %) (tree/lists-headed-by nodes shell-fns))
   (filter (fn [l] (some #(and (= :list (:tag %)) (contains? build-fns (:head %)))
                         (tree/children-of nodes l)))
           (tree/lists-headed-by nodes sql-fns))))

(defn seeds
  "Which vars directly obtain attacker-influenced data, and which hand data to
  an UNSAFE sink. These seed hbt.sonar.callgraph."
  [nodes]
  (let [nsname (namespace-name nodes)
        var-of (fn [l] (when-let [v (enclosing-var nodes l)] [nsname v]))]
    (if-not nsname
      {:taints #{} :reaches #{}}
      {:taints  (into #{} (keep var-of) (tree/lists-headed-by nodes sources))
       :reaches (into #{} (keep var-of) (dangerous-sinks nodes))})))

(defn seeds-of-source [source]
  (let [{:keys [ok? nodes]} (parse/parse source)]
    (when ok? (seeds nodes))))

(defn findings-of-source [source]
  (let [{:keys [ok? nodes]} (parse/parse source)]
    (when ok? (vec (findings nodes)))))
