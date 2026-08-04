(ns hbt.sonar.completeness-sensor
  "Reports whether the analysis had its inputs.

  Runs regardless of which reports are present -- that is the entire point,
  and it is why this sensor does not gate itself on any file existing. The
  measure lands on the project so a quality gate can carry a condition on it;
  the issue lands on the project so a reviewer sees it in the issues list
  rather than in a build log nobody opens."
  (:require [hbt.sonar.completeness :as completeness]
            [hbt.sonar.const :as const]
            [hbt.sonar.metrics-def :as metrics-def]
            [hbt.sonar.report :as report])
  (:import [org.sonar.api.rule RuleKey])
  (:gen-class
   :name hbt.sonar.CompletenessSensor
   :implements [org.sonar.api.batch.sensor.Sensor]))

(defn -describe [_ d]
  (.name d "Clojure analysis completeness")
  (.onlyOnLanguage d const/language-key)
  nil)

(defn present?
  "An input counts as present when a configured or default path is on disk."
  [ctx {:keys [prop default]}]
  (boolean (some report/exists? (report/paths ctx prop default))))

(defn -execute [_ ctx]
  (let [{:keys [percent missing] :as report} (completeness/assess (partial present? ctx))]
    (-> (.newMeasure ctx)
        (.on (.project ctx))
        (.forMetric metrics-def/completeness)
        (.withValue percent)
        (.save))
    (when (seq missing)
      (let [issue (.newIssue ctx)]
        (-> issue
            (.forRule (RuleKey/of const/repository-key "incomplete-analysis"))
            (.at (-> (.newLocation issue)
                     (.on (.project ctx))
                     (.message (completeness/message report))))
            (.save)))))
  nil)
