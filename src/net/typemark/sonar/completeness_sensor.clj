(ns net.typemark.sonar.completeness-sensor
  "Reports whether the analysis had its inputs.

  Runs regardless of which reports are present -- that is the entire point,
  and it is why this sensor does not gate itself on any file existing. The
  measure lands on the project so a quality gate can carry a condition on it;
  the issue lands on the project so a reviewer sees it in the issues list
  rather than in a build log nobody opens."
  (:require [net.typemark.sonar.completeness :as completeness]
            [net.typemark.sonar.const :as const]
            [net.typemark.sonar.metrics-def :as metrics-def]
            [net.typemark.sonar.report :as report])
  (:import [org.sonar.api.rule RuleKey])
  (:gen-class
   :name net.typemark.sonar.CompletenessSensor
   :implements [org.sonar.api.batch.sensor.Sensor]))

(set! *warn-on-reflection* true)

(defn -describe [_ d]
  (.name d "Clojure analysis completeness")
  (.onlyOnLanguage d const/language-key)
  nil)

(defn -execute [_ ctx]
  (let [{:keys [percent missing] :as report} (completeness/assess #(report/present? ctx (:id %)))]
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
