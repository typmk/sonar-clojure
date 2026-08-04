(ns hbt.sonar.coverage-sensor
  "Imports cloverage's lcov output.

  This is the one that decides whether the gate is usable: the default
  `Sonar way` gate fails on `new_coverage < 80`, so a Clojure project with no
  coverage import is red from the first analysis and stays red."
  (:require [hbt.sonar.const :as const]
            [hbt.sonar.lcov :as lcov]
            [hbt.sonar.report :as report])
  (:import [java.io File]
           [org.sonar.api.batch.fs InputFile])
  (:gen-class
   :name hbt.sonar.CloverageSensor
   :implements [org.sonar.api.batch.sensor.Sensor]))

(defn -describe [_ d]
  (.name d "cloverage")
  (.onlyOnLanguage d const/language-key)
  nil)

(defn- import-report! [ctx ^File f]
  (let [parsed (lcov/parse (slurp f))
        tally  (atom {:files 0 :lines 0 :unmatched 0})]
    (doseq [[filename lines] parsed]
      (if-let [^InputFile in (report/input-file ctx filename)]
        (let [c (.onFile (.newCoverage ctx) in)]
          (doseq [[line hits] lines]
            (.lineHits c (int line) (int hits)))
          (.save c)
          (swap! tally #(-> % (update :files inc) (update :lines + (count lines)))))
        (swap! tally update :unmatched inc)))
    (let [{:keys [files lines unmatched]} @tally
          {:keys [hit]} (lcov/covered-summary parsed)]
      (println (format "cloverage %s: %d files, %d lines, %d hit"
                       (.getName f) files lines hit))
      (when (pos? unmatched)
        (println (format "cloverage %s: %d files in the report are not indexed by Sonar -- their coverage is lost"
                         (.getName f) unmatched))))))

(defn -execute [_ ctx]
  (doseq [^File f (report/paths ctx const/coverage-paths-prop const/default-coverage)]
    (if (report/exists? f)
      (import-report! ctx f)
      ;; Silence here reads as 0% coverage, which fails the gate for a reason
      ;; that has nothing to do with the tests.
      (println "cloverage report not found:" (.getPath f)
               "-- coverage will be reported as 0% and the quality gate will fail on it")))
  nil)
