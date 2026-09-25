(ns net.typemark.sonar.coverage-sensor
  "Imports cloverage coverage.

  This is the one that decides whether the gate is usable: the default
  `Sonar way` gate fails on `new_coverage < 80`, so a Clojure project with no
  coverage import is red from the first analysis and stays red.

  Prefers codecov.json over lcov. cloverage's lcov reporter writes
  `DA:<line>,<covered-form-count>`, so a line where one form of five ran is
  recorded as covered -- measured on this project, 22 of 451 instrumented
  lines were partial and every one read as fully covered. codecov.json keeps
  the distinction."
  (:require [net.typemark.sonar.const :as const]
            [net.typemark.sonar.coverage :as coverage]
            [net.typemark.sonar.report :as report])
  (:import [java.io File]
           [org.sonar.api.batch.fs InputFile])
  (:gen-class
   :name net.typemark.sonar.CloverageSensor
   :implements [org.sonar.api.batch.sensor.Sensor]))

(set! *warn-on-reflection* true)

(defn -describe [_ d]
  (.name d "cloverage")
  (.onlyOnLanguage d const/language-key)
  nil)

(defn- save-file! [ctx ^InputFile in lines]
  (let [c (.onFile (.newCoverage ctx) in)]
    (doseq [[line {:keys [hits partial?]}] lines]
      (.lineHits c (int line) (int hits))
      (when partial?
        (.conditions c (int line) (int 2) (int 1))))
    (.save c)))

(defn- import-report! [ctx ^File f]
  (let [parsed (coverage/read-report f)
        tally  (atom {:files 0 :lines 0 :unmatched 0})]
    (doseq [[filename lines] parsed]
      (if-let [in (report/input-file ctx filename)]
        (do (save-file! ctx in lines)
            (swap! tally #(-> % (update :files inc) (update :lines + (count lines)))))
        (swap! tally update :unmatched inc)))
    (let [{:keys [files lines unmatched]} @tally
          partials (reduce + 0 (map (fn [m] (count (filter :partial? (vals m)))) (vals parsed)))]
      (println (format "cloverage %s: %d files, %d lines, %d partial"
                       (.getName f) files lines partials))
      (when (and (pos? lines) (not (coverage/codecov? f)))
        (println (str "cloverage " (.getName f)
                      ": lcov cannot express partial coverage, so partially covered"
                      " lines are reported as covered. Prefer codecov.json.")))
      (when (pos? unmatched)
        (println (format "cloverage %s: %d files in the report are not indexed by Sonar -- their coverage is lost"
                         (.getName f) unmatched))))))

(defn -execute [_ ctx]
  (doseq [^File f (report/for-input ctx :coverage)]
    (if (report/exists? f)
      (import-report! ctx f)
      (println "cloverage report not found:" (.getPath f)
               "-- coverage will be reported as 0% and the quality gate will fail on it")))
  nil)
