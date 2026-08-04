(ns au.com.heisenbergtech.sonar.external-sensor
  "Imports splint, clj-holmes, eastwood and nvd-clojure findings as external
  issues backed by ad-hoc rules."
  (:require [au.com.heisenbergtech.sonar.const :as const]
            [au.com.heisenbergtech.sonar.external :as external]
            [au.com.heisenbergtech.sonar.external-rules :as external-rules]
            [au.com.heisenbergtech.sonar.report :as report])
  (:import [java.io File]
           [org.sonar.api.batch.fs InputFile]
           [org.sonar.api.batch.rule Severity]
           [org.sonar.api.issue.impact SoftwareQuality]
           [org.sonar.api.rules CleanCodeAttribute RuleType])
  (:gen-class
   :name au.com.heisenbergtech.sonar.ExternalAnalyzerSensor
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

(defn- save-issue!
  "The issue's type and software quality come from the ENGINE, not a constant.

  Both were hardcoded to CODE_SMELL and MAINTAINABILITY, so every finding from
  clj-holmes, nvd-clojure and opengrep -- all three declared SECURITY /
  VULNERABILITY -- was filed as a maintainability code smell. Worse, the ad-hoc
  rule's default impact said SECURITY while the issue's impact said
  MAINTAINABILITY, so the severity a reviewer saw came from whichever of the
  two Sonar chose to show: measured, an opengrep finding derived as HIGH
  appeared on the dashboard as MEDIUM."
  [ctx ^InputFile f {:keys [engine rule message line col end-line end-col severity]}]
  (let [issue (.newExternalIssue ctx)
        {:keys [quality type]} (get external/engines engine
                                    {:quality "MAINTAINABILITY" :type "CODE_SMELL"})]
    (-> issue
        (.engineId engine)
        (.ruleId rule)
        (.type (RuleType/valueOf ^String type))
        (.severity Severity/MAJOR)
        (.addImpact (SoftwareQuality/valueOf ^String quality)
                    (get impact-severity severity
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
      (let [known (set (map :key (external-rules/catalogue engine-id)))]
        (doseq [[e r] (external/rule-ids fs) :when (not (contains? known r))]
          (declare-rule! ctx e r))
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
