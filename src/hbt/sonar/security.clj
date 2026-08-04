(ns hbt.sonar.security
  "Security rules for Clojure, and the local dataflow that links a source to
  a sink.

  What this is NOT: SonarSource's taint engine. That is closed to third-party
  plugins and runs only for their own analyzers, so nothing here plugs into
  it. This tracks a value bound by `let`/`fn` from a known source to a known
  sink *within one form* -- intraprocedural, no interprocedural summaries, no
  alias analysis, no collection element tracking. It finds the direct case
  and says so, rather than implying coverage it does not have.

  What it is for: Clojure has no security ruleset anywhere -- not in Sonar,
  not in clj-kondo's defaults. These are the injection and crypto-misuse
  shapes that actually occur in Clojure, each carrying its CWE so the
  findings mean something to a reviewer who does not write Clojure."
  (:require [hbt.sonar.parse :as parse]
            [hbt.sonar.tree :as tree]))

;; ---------------------------------------------------------------------------
;; Rule catalogue. `:hotspot?` marks a rule that flags something a human must
;; judge rather than something known to be wrong -- Sonar reviews those
;; separately, and mixing the two makes both easier to ignore.

(def rule-keys
  "Every rule this namespace can raise. Title, severity, CWE, remediation and
  prose live in org/sonar/l10n/clj/rules/clj-kondo/<key>.{json,html} -- see
  hbt.sonar.metadata for why."
  ["eval-of-dynamic-value" "read-string-untrusted" "shell-command-injection"
   "sql-string-built" "hardcoded-credential" "xml-external-entity"
   "interprocedural-taint" "shell-invocation" "reflective-call"
   "permissive-file-permissions"])

;; ---------------------------------------------------------------------------
;; Sources and sinks.

(def ^:private sources
  "Forms whose result is attacker-influenced. Deliberately small: a false
  source produces a false flow, and a security rule nobody trusts is worse
  than no rule."
  #{"slurp" "read-line" "System/getenv" "System/getProperty"
    ".getParameter" ".getHeader" ".getQueryString" ".getInputStream"
    ;; Ring destructuring: (:params req) is a list headed by the keyword
    ":params" ":query-params" ":form-params" ":body" ":json-params" ":headers"
    ":query-string" ":path-params" ":multipart-params"})

(def ^:private eval-fns        #{"eval" "load-string" "load-reader"})
(def ^:private read-string-fns #{"read-string" "clojure.core/read-string"})
(def ^:private shell-fns       #{"sh" "clojure.java.shell/sh" ".exec" "shell"})
(def ^:private sql-fns         #{"query" "execute!" "jdbc/query" "jdbc/execute!"
                                 "sql/query" "db/query" "execute-one!"})
(def ^:private build-fns       #{"str" "format" "clojure.core/str" "clojure.core/format"})
(def ^:private reflect-fns     #{"resolve" "ns-resolve" "Class/forName" "requiring-resolve"})
(def ^:private xml-fns         #{"clojure.data.xml/parse" "xml/parse" "parse-str" "xml/parse-str"})

(def ^:private credential-name
  "Anchored on segment boundaries. Unanchored, `bypass` matches `pass` and
  `tokenizer` matches `token` -- and a security rule that cries wolf is a
  security rule nobody reads."
  #"(?i)(^|[-_*/.])(passwords?|passwds?|secrets?|api[-_]?keys?|tokens?|credentials?|private[-_]?keys?|access[-_]?keys?|client[-_]?secrets?)([-_*?!]|$)")


;; ---------------------------------------------------------------------------
;; Detection over the parse tree.

(defn- finding [rule node message & [flow]]
  (cond-> {:rule rule
           :line (:line node) :col (:col node)
           :end-line (:end-line node) :end-col (:end-col node)
           :message message}
    flow (assoc :flow flow)))

(defn- dynamic-arg?
  "True when a call's first argument is not a literal -- i.e. computed."
  [nodes lst]
  (let [a (tree/first-argument nodes lst)]
    (and a (not (tree/literal? a)))))

(defn- any-dynamic-arg?
  "True when ANY argument is computed. A shell call is dangerous because of
  the argument that carries the payload, which is rarely the first one --
  `(sh \"sh\" \"-c\" cmd)` is the shape that matters."
  [nodes lst]
  (->> (tree/children-of nodes lst)
       (remove #(= :trivia (:type %)))
       (remove #(= (:head lst) (:text %)))
       (filter #(contains? #{:symbol :list} (if (= :list (:tag %)) :list (:type %))))
       (some #(not (tree/literal? %)))
       boolean))

(defn- tainted-locals
  "Local names bound directly from a source call, with the binding node.
  The whole of this namespace's dataflow: one hop, same form."
  [nodes]
  (into {}
        (for [src  (tree/lists-headed-by nodes sources)
              :let [binding (->> nodes
                                 (filter #(and (= :symbol (:type %))
                                               (= (:line %) (:line src))
                                               (< (:col %) (:col src))))
                                 last)]
              :when binding]
          [(:text binding) {:source src :binding binding}])))

(defn- flow-to
  "A source -> sink flow when a sink argument names a tainted local."
  [tainted nodes lst]
  (some (fn [n]
          (when-let [t (get tainted (:text n))]
            [{:line (:line (:source t)) :col (:col (:source t))
              :end-line (:end-line (:source t)) :end-col (:end-col (:source t))
              :message "value originates here"}
             {:line (:line n) :col (:col n) :end-line (:end-line n) :end-col (:end-col n)
              :message "and reaches the sink here"}]))
        (tree/children-of nodes lst)))

(defn findings
  "All security findings for one parsed file."
  [nodes]
  (let [tainted (tainted-locals nodes)
        flow    #(flow-to tainted nodes %)]
    (concat
     (for [l (tree/lists-headed-by nodes eval-fns)
           :when (dynamic-arg? nodes l)]
       (finding "eval-of-dynamic-value" l
                (str (:head l) " is called on a computed value, which executes whatever it contains")
                (flow l)))

     (for [l (tree/lists-headed-by nodes read-string-fns)]
       (assoc (finding "read-string-untrusted" l
                       "clojure.core/read-string evaluates #= forms; use clojure.edn/read-string"
                       (flow l))
              ;; The head symbol's own span, so the edit replaces the call
              ;; name and nothing else.
              :quick-fix {:message "Replace with clojure.edn/read-string"
                          :text "edn/read-string"
                          :line (:line l) :col (inc (:col l))
                          :end-line (:line l)
                          :end-col (+ (inc (:col l)) (count (:head l)))}))

     (for [l (tree/lists-headed-by nodes shell-fns)
           :when (any-dynamic-arg? nodes l)]
       (finding "shell-command-injection" l
                "shell argument is built from a computed value"
                (flow l)))

     (for [l (tree/lists-headed-by nodes shell-fns)
           :when (not (any-dynamic-arg? nodes l))]
       (finding "shell-invocation" l "shell invocation -- confirm no argument is caller-controlled"))

     ;; SQL assembled by str/format and handed to a query fn
     (for [l (tree/lists-headed-by nodes sql-fns)
           :when (some #(and (= :list (:tag %)) (contains? build-fns (:head %)))
                       (tree/children-of nodes l))]
       (finding "sql-string-built" l
                "SQL statement is assembled by string building; pass parameters as values"
                (flow l)))

     ;; weak-hash-algorithm and insecure-random moved to hbt.sonar.interop,
     ;; which resolves the actual class through the ns form's :import rather
     ;; than matching "MD5" anywhere a string happens to contain it.

     ;; a credential-shaped name bound to a string literal
     (for [l (tree/lists-headed-by nodes #{"def" "defonce"})
           :let [nm (tree/first-argument nodes l)
                 v  (->> (tree/children-of nodes l)
                         (remove #(= :trivia (:type %)))
                         (filter #(= :string (:type %)))
                         first)]
           :when (and nm v (re-find credential-name (:text nm))
                      (> (count (:text v)) 6))]
       (finding "hardcoded-credential" v
                (str "credential-shaped name '" (:text nm) "' is bound to a literal")))

     (for [l (tree/lists-headed-by nodes xml-fns)]
       (finding "xml-external-entity" l
                "confirm this parser has external entity resolution disabled"))

     (for [l (tree/lists-headed-by nodes reflect-fns)
           :when (dynamic-arg? nodes l)]
       (finding "reflective-call" l
                (str (:head l) " selects code by a computed name")))

     (for [n nodes
           :when (and (= :string (:type n)) (not (:commented? n))
                      (re-find #"\"(0?7[0-7][0-7]|rwxrwxrwx|.......rw.)\"" (:text n)))]
       (finding "permissive-file-permissions" n
                "world-accessible file mode")))))

(defn- namespace-name
  "The ns this file declares, or nil."
  [nodes]
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

  Seeding the interprocedural pass from raw function names was wrong: it
  flagged `(jdbc/execute! ds [\"... WHERE org_id = ?\" org-id])` -- a
  correctly parameterised query -- because the name matched. The seeds now
  use the same predicates the direct rules use, so the two passes agree on
  what danger is."
  [nodes]
  (concat
   (filter #(dynamic-arg? nodes %) (tree/lists-headed-by nodes eval-fns))
   (tree/lists-headed-by nodes read-string-fns)
   (filter #(any-dynamic-arg? nodes %) (tree/lists-headed-by nodes shell-fns))
   (filter (fn [l] (some #(and (= :list (:tag %)) (contains? build-fns (:head %)))
                         (tree/children-of nodes l)))
           (tree/lists-headed-by nodes sql-fns))))

(defn seeds
  "Which vars in this file directly obtain attacker-influenced data, and
  which directly hand data to an UNSAFE sink. These seed the interprocedural
  propagation in hbt.sonar.callgraph."
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
