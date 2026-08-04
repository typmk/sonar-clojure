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
  (:require [hbt.sonar.parse :as parse]))

;; ---------------------------------------------------------------------------
;; Rule catalogue. `:hotspot?` marks a rule that flags something a human must
;; judge rather than something known to be wrong -- Sonar reviews those
;; separately, and mixing the two makes both easier to ignore.

(def rules
  [{:key "eval-of-dynamic-value"
    :name "eval must not be called on a computed value"
    :cwe [95 94] :owasp ["A3"] :severity "HIGH" :quality "SECURITY"
    :doc "<p><code>eval</code> on anything other than a quoted literal executes whatever the value contains.</p>"}

   {:key "read-string-untrusted"
    :name "clojure.core/read-string must not read untrusted input"
    :cwe [502] :owasp ["A8"] :severity "HIGH" :quality "SECURITY"
    :doc (str "<p><code>clojure.core/read-string</code> honours <code>*read-eval*</code> and "
              "evaluates <code>#=</code> forms. Use <code>clojure.edn/read-string</code>, which does not.</p>")}

   {:key "shell-command-injection"
    :name "Shell arguments must not be built from computed values"
    :cwe [78] :owasp ["A3"] :severity "HIGH" :quality "SECURITY"
    :doc "<p>A shell argument assembled from a value the caller controls is a command injection.</p>"}

   {:key "sql-string-built"
    :name "SQL must not be assembled by string concatenation"
    :cwe [89] :owasp ["A3"] :severity "HIGH" :quality "SECURITY"
    :doc "<p>Pass parameters as values so the driver binds them, rather than building the statement with <code>str</code> or <code>format</code>.</p>"}

   {:key "weak-hash-algorithm"
    :name "Broken hash algorithm"
    :cwe [327 328] :owasp ["A2"] :severity "HIGH" :quality "SECURITY"
    :doc "<p>MD5 and SHA-1 are broken for any security purpose. For passwords use a memory-hard KDF, not a hash.</p>"}

   {:key "insecure-random"
    :name "java.util.Random is not a secure source of randomness"
    :cwe [338 330] :owasp ["A2"] :severity "MEDIUM" :quality "SECURITY"
    :doc "<p><code>java.util.Random</code> and <code>rand</code> are predictable. Use <code>java.security.SecureRandom</code> for anything a attacker must not guess.</p>"}

   {:key "hardcoded-credential"
    :name "Credential must not be hardcoded"
    :cwe [798 259] :owasp ["A7"] :severity "HIGH" :quality "SECURITY"
    :doc "<p>A literal bound to a credential-shaped name ships the secret in the artifact and in version control.</p>"}

   {:key "xml-external-entity"
    :name "XML parsing must disable external entities"
    :cwe [611] :owasp ["A5"] :severity "HIGH" :quality "SECURITY"
    :doc "<p>A parser that resolves external entities will fetch attacker-named URLs and read local files.</p>"}

   ;; --- hotspots: review required, not defects ---
   {:key "shell-invocation" :hotspot? true
    :name "Shell invocation should be reviewed"
    :cwe [78] :owasp ["A3"] :severity "MEDIUM" :quality "SECURITY"
    :doc "<p>Shelling out is legitimate; confirm no part of the command is caller-controlled.</p>"}

   {:key "reflective-call" :hotspot? true
    :name "Reflective invocation should be reviewed"
    :cwe [470] :owasp ["A8"] :severity "MEDIUM" :quality "SECURITY"
    :doc "<p><code>resolve</code>, <code>ns-resolve</code> and <code>Class/forName</code> on a computed name select code at runtime.</p>"}

   {:key "permissive-file-permissions" :hotspot? true
    :name "File permissions should be reviewed"
    :cwe [732] :owasp ["A1"] :severity "MEDIUM" :quality "SECURITY"
    :doc "<p>World-readable or world-writable modes on files holding secrets.</p>"}])

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

(def ^:private weak-hash #"(?i)\"(MD5|SHA-?1|MD2|MD4)\"")

;; ---------------------------------------------------------------------------
;; Detection over the parse tree.

(defn- children-of
  "Nodes strictly inside `n`, by position -- the flat stream keeps document
  order, so a node's subtree is the run that starts after it and ends before
  its close."
  [nodes n]
  (->> nodes
       (filter #(and (> (:line %) (:line n))
                     (<= (:end-line %) (:end-line n))))
       (concat (filter #(and (= (:line %) (:line n))
                             (> (:col %) (:col n))
                             (<= (:end-line %) (:end-line n)))
                       nodes))
       distinct))

(defn- literal?
  "A value that cannot carry an attacker's payload. A quoted form counts:
  `(eval '(inc 1))` is the commonest safe use of eval, and flagging it would
  train people to ignore the rule."
  [{:keys [type tag]}]
  (or (contains? #{:string :number :char :regex} type)
      (contains? #{:quote :syntax-quote} tag)))

(defn- lists-headed-by
  "Live list nodes whose head symbol is in `heads`."
  [nodes heads]
  (filter #(and (= :list (:tag %))
                (not (:commented? %))
                (contains? heads (:head %)))
          nodes))

(defn- first-argument
  "The node in argument position 1 of a list, or nil."
  [nodes lst]
  (->> (children-of nodes lst)
       (remove #(= :trivia (:type %)))
       (drop-while #(= (:head lst) (:text %)))
       (remove #(= (:head lst) (:text %)))
       first))

(defn- finding [rule node message & [flow]]
  (cond-> {:rule rule
           :line (:line node) :col (:col node)
           :end-line (:end-line node) :end-col (:end-col node)
           :message message}
    flow (assoc :flow flow)))

(defn- dynamic-arg?
  "True when a call's first argument is not a literal -- i.e. computed."
  [nodes lst]
  (let [a (first-argument nodes lst)]
    (and a (not (literal? a)))))

(defn- any-dynamic-arg?
  "True when ANY argument is computed. A shell call is dangerous because of
  the argument that carries the payload, which is rarely the first one --
  `(sh \"sh\" \"-c\" cmd)` is the shape that matters."
  [nodes lst]
  (->> (children-of nodes lst)
       (remove #(= :trivia (:type %)))
       (remove #(= (:head lst) (:text %)))
       (filter #(contains? #{:symbol :list} (if (= :list (:tag %)) :list (:type %))))
       (some #(not (literal? %)))
       boolean))

(defn- tainted-locals
  "Local names bound directly from a source call, with the binding node.
  The whole of this namespace's dataflow: one hop, same form."
  [nodes]
  (into {}
        (for [src  (lists-headed-by nodes sources)
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
        (children-of nodes lst)))

(defn findings
  "All security findings for one parsed file."
  [nodes]
  (let [tainted (tainted-locals nodes)
        flow    #(flow-to tainted nodes %)]
    (concat
     (for [l (lists-headed-by nodes eval-fns)
           :when (dynamic-arg? nodes l)]
       (finding "eval-of-dynamic-value" l
                (str (:head l) " is called on a computed value, which executes whatever it contains")
                (flow l)))

     (for [l (lists-headed-by nodes read-string-fns)]
       (finding "read-string-untrusted" l
                "clojure.core/read-string evaluates #= forms; use clojure.edn/read-string"
                (flow l)))

     (for [l (lists-headed-by nodes shell-fns)
           :when (any-dynamic-arg? nodes l)]
       (finding "shell-command-injection" l
                "shell argument is built from a computed value"
                (flow l)))

     (for [l (lists-headed-by nodes shell-fns)
           :when (not (any-dynamic-arg? nodes l))]
       (finding "shell-invocation" l "shell invocation -- confirm no argument is caller-controlled"))

     ;; SQL assembled by str/format and handed to a query fn
     (for [l (lists-headed-by nodes sql-fns)
           :when (some #(and (= :list (:tag %)) (contains? build-fns (:head %)))
                       (children-of nodes l))]
       (finding "sql-string-built" l
                "SQL statement is assembled by string building; pass parameters as values"
                (flow l)))

     (for [n nodes
           :when (and (= :string (:type n)) (not (:commented? n))
                      (re-find weak-hash (:text n)))]
       (finding "weak-hash-algorithm" n
                (str "broken hash algorithm " (:text n))))

     (for [n nodes
           :when (and (= :symbol (:type n)) (not (:commented? n))
                      (contains? #{"java.util.Random." "java.util.Random" "Random."} (:text n)))]
       (finding "insecure-random" n "java.util.Random is predictable; use java.security.SecureRandom"))

     ;; a credential-shaped name bound to a string literal
     (for [l (lists-headed-by nodes #{"def" "defonce"})
           :let [nm (first-argument nodes l)
                 v  (->> (children-of nodes l)
                         (remove #(= :trivia (:type %)))
                         (filter #(= :string (:type %)))
                         first)]
           :when (and nm v (re-find credential-name (:text nm))
                      (> (count (:text v)) 6))]
       (finding "hardcoded-credential" v
                (str "credential-shaped name '" (:text nm) "' is bound to a literal")))

     (for [l (lists-headed-by nodes xml-fns)]
       (finding "xml-external-entity" l
                "confirm this parser has external entity resolution disabled"))

     (for [l (lists-headed-by nodes reflect-fns)
           :when (dynamic-arg? nodes l)]
       (finding "reflective-call" l
                (str (:head l) " selects code by a computed name")))

     (for [n nodes
           :when (and (= :string (:type n)) (not (:commented? n))
                      (re-find #"\"(0?7[0-7][0-7]|rwxrwxrwx|.......rw.)\"" (:text n)))]
       (finding "permissive-file-permissions" n
                "world-accessible file mode")))))

(defn findings-of-source [source]
  (let [{:keys [ok? nodes]} (parse/parse source)]
    (when ok? (vec (findings nodes)))))
