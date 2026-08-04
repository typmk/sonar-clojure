(ns hbt.sonar.external-sensor
  "Imports splint, clj-holmes, eastwood and nvd-clojure findings as external
  issues backed by ad-hoc rules."
  (:require [hbt.sonar.const :as const]
            [hbt.sonar.external :as external]
            [hbt.sonar.report :as report])
  (:import [java.io File]
           [org.sonar.api.batch.fs InputFile]
           [org.sonar.api.batch.rule Severity]
           [org.sonar.api.issue.impact SoftwareQuality]
           [org.sonar.api.rules CleanCodeAttribute RuleType])
  (:gen-class
   :name hbt.sonar.ExternalAnalyzerSensor
   :implements [org.sonar.api.batch.sensor.Sensor]))

(defn -describe [_ d]
  (.name d "Clojure external analyzers")
  (.onlyOnLanguage d const/language-key)
  nil)

(def ^:private impact-severity
  {"HIGH" org.sonar.api.issue.impact.Severity/HIGH
   "MEDIUM" org.sonar.api.issue.impact.Severity/MEDIUM
   "LOW" org.sonar.api.issue.impact.Severity/LOW})

(defn- declare-rule! [ctx engine-id rule-id]
  (let [{:keys [name quality type]} (get external/engines engine-id
                                         {:name engine-id :quality "MAINTAINABILITY"
                                          :type "CODE_SMELL"})]
    (-> (.newAdHocRule ctx)
        (.engineId engine-id)
        (.ruleId rule-id)
        (.name (str name ": " rule-id))
        (.description (str "<p>Reported by <code>" name "</code>. "
                           "Configure or disable it in that tool's own config, "
                           "not in SonarQube -- an ad-hoc rule has no quality profile.</p>"))
        (.type (RuleType/valueOf ^String type))
        (.cleanCodeAttribute CleanCodeAttribute/LOGICAL)
        (.severity Severity/MAJOR)
        (.addDefaultImpact (SoftwareQuality/valueOf ^String quality)
                           org.sonar.api.issue.impact.Severity/MEDIUM)
        (.save))))

(defn- save-issue! [ctx ^InputFile f {:keys [engine rule message line col end-line end-col severity]}]
  (let [issue (.newExternalIssue ctx)]
    (-> issue
        (.engineId engine)
        (.ruleId rule)
        (.type RuleType/CODE_SMELL)
        (.severity Severity/MAJOR)
        (.addImpact SoftwareQuality/MAINTAINABILITY (get impact-severity severity
                                                        org.sonar.api.issue.impact.Severity/MEDIUM))
        (.at (-> (.newLocation issue)
                 (.on f)
                 (.at (try (.newRange f (int line) (int (dec col)) (int end-line) (int (dec end-col)))
                           (catch Exception _ (.selectLine f (int line)))))
                 (.message message))))
    (.save issue)))

(defn- import-engine! [ctx engine-id ^File f]
  (let [fs (external/findings engine-id (slurp f))]
    (if (nil? fs)
      (println (format "%s %s: not a recognised report shape -- no findings imported"
                       engine-id (.getName f)))
      (do
        (doseq [[e r] (external/rule-ids fs)] (declare-rule! ctx e r))
        (let [saved (reduce (fn [n finding]
                              (if-let [in (report/input-file ctx (:filename finding))]
                                (do (save-issue! ctx in finding) (inc n))
                                n))
                            0 fs)]
          (println (format "%s %s: %d of %d findings imported"
                           engine-id (.getName f) saved (count fs)))
          (when (< saved (count fs))
            (println (format "%s %s: %d findings dropped -- file not indexed by Sonar"
                             engine-id (.getName f) (- (count fs) saved)))))))))

(defn -execute [_ ctx]
  (doseq [[engine-id prop] const/external-report-props
          ^File f (report/paths ctx prop nil)
          :when (and f (report/exists? f))]
    (import-engine! ctx engine-id f))
  nil)
