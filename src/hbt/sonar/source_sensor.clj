(ns hbt.sonar.source-sensor
  "Everything Sonar knows about a Clojure file that is not an issue: size,
  complexity, duplication tokens, syntax highlighting and the symbol table.

  Without the measures here, ncloc is zero and every ratio on the dashboard
  -- comment density, duplication density, technical-debt ratio -- divides
  by nothing."
  (:require [hbt.sonar.analysis :as analysis]
            [hbt.sonar.const :as const]
            [hbt.sonar.highlight :as hl]
            [hbt.sonar.metrics :as metrics]
            [hbt.sonar.parse :as parse]
            [hbt.sonar.report :as report]
            [hbt.sonar.security :as security])
  (:import [java.io File]
           [org.sonar.api.batch.fs InputFile]
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

(defn- save-security! [ctx ^InputFile f findings]
  (doseq [{:keys [rule flow] :as finding} findings]
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

(defn- measure-file! [ctx by-file ^InputFile f]
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
        (save-measures! ctx f ms)
        (save-line-data! ctx f (metrics/line-data nodes))
        (save-security! ctx f (security/findings nodes))
        (save-cpd! ctx f leaves)
        (save-highlighting! ctx f leaves)
        (save-symbols! ctx f (or (get by-file (str (.path f)))
                                 (get by-file (.toString (.relativePath f)))
                                 []))
        ms))))

(defn -execute [_ ctx]
  (let [fs      (.fileSystem ctx)
        by-file (analysis-symbols ctx)
        inputs  (vec (.inputFiles fs (.hasLanguage (.predicates fs) const/language-key)))
        results (mapv #(measure-file! ctx by-file %) inputs)
        ok      (remove nil? results)]
    (println (format "Clojure: measured %d files, %d ncloc"
                     (count ok) (reduce + 0 (map :ncloc ok))))
    (when-let [failed (seq (filter nil? results))]
      (println (format "Clojure: %d files could not be parsed -- their lines are missing from ncloc"
                       (count failed)))))
  nil)
