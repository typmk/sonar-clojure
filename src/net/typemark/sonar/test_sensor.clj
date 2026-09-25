(ns net.typemark.sonar.test-sensor
  "Imports kaocha's JUnit XML as Sonar's test-execution measures.

  Without it a project with 634 passing tests reports none, and the only
  evidence Sonar has that the code is exercised at all is the coverage
  percentage -- which says how much ran, never how much was checked."
  (:require [net.typemark.sonar.junit :as junit]
            [net.typemark.sonar.report :as report])
  (:import [java.io File]
           [org.sonar.api.batch.fs InputFile]
           [org.sonar.api.measures CoreMetrics]))

(set! *warn-on-reflection* true)

(def ^:private metric
  {:tests       CoreMetrics/TESTS
   :failures    CoreMetrics/TEST_FAILURES
   :errors      CoreMetrics/TEST_ERRORS
   :skipped     CoreMetrics/SKIPPED_TESTS})

(defn- test-file
  "Find the indexed file a test namespace lives in. Sonar's own predicates
  do the matching, so a project laying tests out unusually still resolves."
  [ctx nsname]
  (let [base (junit/ns->path nsname)]
    (some #(report/input-file ctx (str base %))
          [".clj" ".cljc" ".cljs"])))

(defn- save-for-namespace! [ctx nsname m]
  (when-let [^InputFile f (test-file ctx nsname)]
    (doseq [[k metric-obj] metric
            :let [v (get m k)]
            :when v]
      (-> (.newMeasure ctx) (.on f) (.forMetric metric-obj) (.withValue (int v)) (.save)))
    (-> (.newMeasure ctx) (.on f) (.forMetric CoreMetrics/TEST_EXECUTION_TIME)
        (.withValue (long (:duration-ms m 0))) (.save))
    true))

(defn- import-report! [ctx ^File f]
  (let [parsed (junit/parse (slurp f))
        placed (doall (map (fn [[nsname m]] (save-for-namespace! ctx nsname m)) parsed))
        t      (junit/totals parsed)
        missed (count (remove true? placed))]
    (println (format "kaocha %s: %d tests, %d failures, %d errors, %d skipped"
                     (.getName f) (:tests t) (:failures t) (:errors t) (:skipped t)))
    (when (pos? missed)
      (println (format "kaocha %s: %d namespaces had no indexed file -- their results are missing. Check sonar.tests."
                       (.getName f) missed)))))

(defn execute! [ctx]
  (report/each ctx :tests #(import-report! ctx %))
  nil)
