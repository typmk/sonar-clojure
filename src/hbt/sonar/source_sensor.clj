(ns hbt.sonar.source-sensor
  "Everything Sonar knows about a Clojure file that is not an issue: size,
  complexity, duplication tokens, syntax highlighting and the symbol table.

  Without the measures here, ncloc is zero and every ratio on the dashboard
  -- comment density, duplication density, technical-debt ratio -- divides
  by nothing."
  (:require [clojure.string :as str]
            [hbt.sonar.analysis :as analysis]
            [hbt.sonar.const :as const]
            [hbt.sonar.highlight :as hl]
            [hbt.sonar.metrics :as metrics]
            [hbt.sonar.parse :as parse]
            [hbt.sonar.report :as report]
            [hbt.sonar.access :as access]
            [hbt.sonar.concurrency :as concurrency]
            [hbt.sonar.regex :as regex]
            [hbt.sonar.tests :as tests]
            [hbt.sonar.web :as web]
            [hbt.sonar.interop :as interop]
            [hbt.sonar.security :as security]
            [hbt.sonar.coverage-sensor :as coverage]
            [hbt.sonar.callgraph :as callgraph])
  (:import [java.io File]
           [org.sonar.api.batch.fs InputFile InputFile$Status InputFile$Type]
           [org.sonar.api.batch.sensor.issue NewIssue$FlowType]
           [org.sonar.api.rule RuleKey]
           [org.sonar.api.batch.sensor.highlighting TypeOfText]
           [org.sonar.api.measures CoreMetrics])
  (:gen-class
   :name hbt.sonar.ClojureSourceSensor
   :implements [org.sonar.api.batch.sensor.Sensor]))

(defn -describe [_ d]
  (.name d "Clojure source measures and security")
  (.onlyOnLanguage d const/language-key)
  nil)

(def ^:private metric
  {:ncloc         CoreMetrics/NCLOC
   :comment-lines CoreMetrics/COMMENT_LINES
   :functions     CoreMetrics/FUNCTIONS
   :classes       CoreMetrics/CLASSES
   :statements    CoreMetrics/STATEMENTS
   :complexity    CoreMetrics/COMPLEXITY
   :cognitive     CoreMetrics/COGNITIVE_COMPLEXITY})

(defn- save-measures! [ctx ^InputFile f ms]
  (doseq [[k m] metric
          :let [v (get ms k)]
          :when v]
    (-> (.newMeasure ctx) (.on f) (.forMetric m) (.withValue (int v)) (.save))))

(defn- save-line-data!
  "Which lines are code, and which could have been covered. New-code
  coverage is computed against the executable set, so without this the
  number the quality gate tests is inferred from whatever the coverage
  report happened to mention."
  [ctx ^InputFile f {:keys [ncloc-data executable-data]}]
  (-> (.newMeasure ctx) (.on f) (.forMetric CoreMetrics/NCLOC_DATA)
      (.withValue ncloc-data) (.save))
  (-> (.newMeasure ctx) (.on f) (.forMetric CoreMetrics/EXECUTABLE_LINES_DATA)
      (.withValue executable-data) (.save)))

(defn- location [issue ^InputFile f {:keys [line col end-line end-col message]}]
  (-> (.newLocation issue)
      (.on f)
      (.at (.newRange f (int line) (int (dec col)) (int end-line) (int (dec end-col))))
      (.message message)))

(defn- add-quick-fix!
  "A fix the reviewer can apply from the IDE. Only offered where the
  replacement is mechanical -- a wrong quick fix is worse than none."
  [issue ^InputFile f {:keys [message text line col end-line end-col]}]
  (let [edit (-> (.newInputFileEdit issue) (.on f))
        te   (-> (.newTextEdit edit)
                 (.at (.newRange f (int line) (int (dec col)) (int end-line) (int (dec end-col))))
                 (.withNewText text))]
    (.addInputFileEdit (-> (.newQuickFix issue) (.message message))
                       (.addTextEdit edit te))))

(defn- save-security! [ctx ^InputFile f findings]
  (doseq [{:keys [rule flow quick-fix] :as finding} findings]
    (try
      (let [issue (.newIssue ctx)]
        (.forRule issue (RuleKey/of const/repository-key rule))
        (.at issue (location issue f finding))
        ;; The flow is what makes a taint finding reviewable: it shows where
        ;; the value came from, not just where it landed.
        (when (seq flow)
          (.addFlow issue
                    (mapv #(location issue f %) flow)
                    NewIssue$FlowType/DATA
                    "tainted value"))
        (when quick-fix
          (.addQuickFix issue (add-quick-fix! issue f quick-fix)))
        (.save issue))
      (catch Exception e
        ;; A range Sonar rejects must cost one finding, not the file's rest.
        (println "Clojure: could not save security finding" rule "in"
                 (str (.filename f)) "--" (.getMessage e))))))

(defn- save-cpd! [ctx ^InputFile f tokens]
  (let [cpd (.onFile (.newCpdTokens ctx) f)]
    (doseq [t tokens
            ;; comments are not duplication; two files with the same licence
            ;; header are not two copies of the same code
            :when (not= :comment (:type t))]
      (.addToken cpd (int (:line t)) (int (dec (:col t)))
                 (int (:end-line t)) (int (dec (:end-col t)))
                 ^String (parse/cpd-image t)))
    (.save cpd)))

(defn- save-highlighting! [ctx ^InputFile f tokens]
  (let [h (.onFile (.newHighlighting ctx) f)]
    (doseq [s (hl/spans tokens)]
      (.highlight h (int (:line s)) (int (dec (:col s)))
                  (int (:end-line s)) (int (dec (:end-col s)))
                  (TypeOfText/valueOf ^String (:type s))))
    (.save h)))

(defn- save-symbols! [ctx ^InputFile f syms]
  (when (seq syms)
    (let [t (.onFile (.newSymbolTable ctx) f)]
      (doseq [{:keys [declaration references]} syms
              :let [s (.newSymbol t (int (:line declaration)) (int (dec (:col declaration)))
                                  (int (:end-line declaration)) (int (dec (:end-col declaration))))]]
        (doseq [r references]
          (.newReference s (int (:line r)) (int (dec (:col r)))
                         (int (:end-line r)) (int (dec (:end-col r))))))
      (.save t))))

(defn- analysis-symbols
  "The symbol table needs clj-kondo's analysis output. Absent, everything else
  in this sensor still runs -- navigation degrades, measures do not."
  [ctx]
  (reduce (fn [acc ^File f]
            (if (report/exists? f)
              (merge-with into acc (analysis/symbols (slurp f)))
              (do (println "clj-kondo analysis not found:" (.getPath f)
                           "-- symbol navigation disabled for this run")
                  acc)))
          {}
          (report/paths ctx const/analysis-paths-prop const/default-analysis)))

(defn- cache-key [^InputFile f]
  ;; Sonar's own content hash: the file is unchanged iff this is unchanged.
  (str "hbt.sonar.parse:" (.key f) ":" (.md5Hash f)))

(defn- skip?
  "True when Sonar says this file is unchanged since the last analysis AND
  the previous run cached a result for exactly this content.

  Only measures are skipped, never issues: Sonar carries unchanged files'
  issues forward itself, but a measure not re-reported is a measure lost."
  [ctx ^InputFile f]
  (and (.canSkipUnchangedFiles ctx)
       (.isCacheEnabled ctx)
       (= InputFile$Status/SAME (.status f))
       (.contains (.previousCache ctx) (cache-key f))))

(defn- remember! [ctx ^InputFile f]
  (when (.isCacheEnabled ctx)
    (try
      (.write (.nextCache ctx) (cache-key f) (.getBytes "1" "UTF-8"))
      (catch Exception _
        ;; A duplicate key or a closed cache must not cost the analysis.
        nil))))

(defn- instrumented
  "Which lines the coverage tool actually tracked, keyed by the path it used.
  Ground truth for executable-lines data; the parse-tree heuristic is only a
  fallback for files no report mentions."
  [ctx]
  (reduce (fn [acc ^File f]
            (if (report/exists? f)
              (merge acc (into {} (for [[file lines] (coverage/read-report f)]
                                    [file (set (keys lines))])))
              acc))
          {}
          (report/paths ctx const/coverage-paths-prop const/default-coverage)))

(defn- truth-for
  "Match a file against the coverage report's key, which may or may not carry
  the source root -- cloverage's two writers disagree."
  [by-path ^InputFile f]
  (let [p (str (.path f))]
    (or (get by-path p)
        (some (fn [[k v]] (when (str/ends-with? p (str "/" k)) v)) by-path))))

(defn- measure-file! [ctx by-file truth-by-path seeds ^InputFile f]
  (if (skip? ctx f)
    (do (.copyFromPrevious (.nextCache ctx) (cache-key f)) ::skipped)
    (let [{:keys [ok? nodes error]} (parse/parse (slurp (.inputStream f)))]
    (if-not ok?
      ;; The file contributes no ncloc, so every ratio computed over it is
      ;; wrong. Scanner stdout is not where anyone looks -- raise it as an
      ;; analysis error so the omission is visible in Sonar itself.
      (do (-> (.newAnalysisError ctx)
              (.onFile f)
              (.message (str "Clojure source could not be parsed, so its lines are "
                             "absent from ncloc and every ratio over it: " error))
              (.save))
          (println "Clojure: could not parse" (str (.filename f)) "--" error)
          nil)
      (let [leaves (parse/leaves nodes)
            ms     (metrics/from-nodes nodes)]
        (swap! seeds #(merge-with into % (security/seeds nodes)))
        (save-measures! ctx f ms)
        (save-line-data! ctx f (metrics/line-data nodes (truth-for truth-by-path f)))
        (save-security! ctx f (concat (security/findings nodes)
                                      (interop/all-findings nodes)
                                      (concurrency/findings nodes)
                                      (regex/findings nodes)
                                      (web/findings nodes)
                                      (access/findings nodes)
                                      ;; test rules apply to test files only
                                      (when (= InputFile$Type/TEST (.type f))
                                        (tests/findings nodes))))
        (save-cpd! ctx f leaves)
        (save-highlighting! ctx f leaves)
        (save-symbols! ctx f (or (get by-file (str (.path f)))
                                 (get by-file (.toString (.relativePath f)))
                                 []))
        (remember! ctx f)
        ms)))))

(defn- interprocedural!
  "Taint paths that cross function boundaries. Needs clj-kondo's analysis
  for the call graph, so it is silent without it -- the direct findings are
  unaffected."
  [ctx {:keys [taints reaches] :as seeds}]
  (if (or (empty? taints) (empty? reaches))
    0
    (reduce
     + 0
     (for [^File f (report/paths ctx const/analysis-paths-prop const/default-analysis)
           :when (report/exists? f)]
       (let [fs (callgraph/findings (slurp f) seeds)]
         (doseq [finding fs]
           (when-let [in (report/input-file ctx (:filename finding))]
             (save-security! ctx in [finding])))
         (count fs))))))

(defn -execute [_ ctx]
  (let [fs      (.fileSystem ctx)
        by-file (analysis-symbols ctx)
        inputs  (vec (.inputFiles fs (.hasLanguage (.predicates fs) const/language-key)))
        truth   (instrumented ctx)
        seeds   (atom {:taints #{} :reaches #{}})
        results (mapv #(measure-file! ctx by-file truth seeds %) inputs)
        skipped (count (filter #(= ::skipped %) results))
        ok      (remove #(or (nil? %) (= ::skipped %)) results)]
    (println (format "Clojure: measured %d files, %d ncloc%s"
                     (count ok) (reduce + 0 (map :ncloc ok))
                     (if (pos? skipped) (format " (%d unchanged, from cache)" skipped) "")))
    ;; The interprocedural pass needs every file's seeds, so it runs once the
    ;; per-file walk is done rather than inside it.
    (let [n (interprocedural! ctx @seeds)]
      (when (pos? n)
        (println (format "Clojure: %d interprocedural taint paths" n))))
    (when-let [failed (seq (filter nil? results))]
      (println (format "Clojure: %d files could not be parsed -- their lines are missing from ncloc"
                       (count failed)))))
  nil)
