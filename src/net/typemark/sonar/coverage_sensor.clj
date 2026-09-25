(ns net.typemark.sonar.coverage-sensor
  "Imports cloverage coverage.

  This is the one that decides whether the gate is usable: the default
  `Sonar way` gate fails on `new_coverage < 80`, so a Clojure project with no
  coverage import is red from the first analysis and stays red.

  Reads codecov.json only; `net.typemark.sonar.coverage` says why."
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

(defn- import-parsed! [ctx ^File f parsed]
  (let [tally  (atom {:files 0 :lines 0 :unmatched 0})]
    (doseq [[filename lines] parsed]
      (if-let [in (report/input-file ctx filename)]
        (do (save-file! ctx in lines)
            (swap! tally #(-> % (update :files inc) (update :lines + (count lines)))))
        (swap! tally update :unmatched inc)))
    (let [{:keys [files lines unmatched]} @tally
          partials (reduce + 0 (map (fn [m] (count (filter :partial? (vals m)))) (vals parsed)))]
      (println (format "cloverage %s: %d files, %d lines, %d partial"
                       (.getName f) files lines partials))
      (when (pos? unmatched)
        (println (format "cloverage %s: %d files in the report are not indexed by Sonar -- their coverage is lost"
                         (.getName f) unmatched))))))

(defn- import-report! [ctx ^File f]
  (if-let [parsed (coverage/parse (slurp f))]
    (import-parsed! ctx f parsed)
    (println (str "cloverage " (.getName f) ": not a codecov.json report, so no coverage"
                  " was imported. Produce one with cloverage --codecov."))))

(defn -execute [_ ctx]
  (report/each ctx :coverage #(import-report! ctx %))
  nil)
