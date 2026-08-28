(ns au.com.heisenbergtech.sonar.metrics-def
  "A metric for how much of the analysis actually ran.

  SonarQube has no native notion of an incomplete analysis: a project that was
  never measured and a project that is clean produce the same dashboard. This
  metric makes the difference visible, and because a quality gate can carry a
  condition on any metric, it can be made to fail rather than merely inform."
  (:import [org.sonar.api.measures Metric$Builder Metric$ValueType])
  (:gen-class
   :name au.com.heisenbergtech.sonar.ClojureMetrics
   :implements [org.sonar.api.measures.Metrics]))

(set! *warn-on-reflection* true)

(def completeness-key "clj_analysis_completeness")

(def completeness
  (-> (Metric$Builder. completeness-key
                       "Clojure analysis completeness"
                       Metric$ValueType/PERCENT)
      (.setDescription
       (str "Percentage of the reports this analyzer reads that were present. "
            "Below 100 the dashboard understates findings: a missing clj-kondo "
            "report reads as zero issues, a missing coverage report as 0%."))
      (.setDirection org.sonar.api.measures.Metric/DIRECTION_BETTER)
      (.setQualitative true)
      (.setDomain "Clojure")
      (.create)))

(defn -getMetrics [_] [completeness])
