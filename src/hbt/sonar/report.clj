(ns hbt.sonar.report
  "Locating a report on disk, and matching a path inside it to a file Sonar
  indexed.

  Both sensors and the symbol loader had their own copy of this. It is the
  code path where a mistake means findings silently disappear between the
  linter and the dashboard, so it exists once."
  (:require [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [java.io File]))

(defn paths
  "The configured report paths for `prop`, or `default` when unset, each
  resolved against the module base unless already absolute."
  [ctx prop default]
  (let [base  (.baseDir (.fileSystem ctx))
        given (remove str/blank? (.getStringArray (.config ctx) prop))]
    (for [p (if (seq given) given (if default [default] []))]
      (let [f (io/file p)]
        (if (.isAbsolute f) f (io/file base p))))))

(defn exists? [^File f] (.isFile f))

(defn input-file
  "The InputFile for a path named inside a report, or nil.

  Three attempts, because the tools disagree about what a path is relative
  to. cloverage's lcov writes `src/hbt/sonar/x.clj` while its codecov writer
  drops the source root and writes `hbt/sonar/x.clj`; clj-kondo writes
  whatever its working directory made it. A path that fails to resolve costs
  the finding silently, so it is worth trying all three.

  The suffix match is last and requires a path separator boundary, so
  `a/foo.clj` cannot match `b/megafoo.clj`."
  [ctx ^String filename]
  (let [fs  (.fileSystem ctx)
        ps  (.predicates fs)
        abs (.getAbsolutePath (io/file (.baseDir fs) filename))]
    (or (.inputFile fs (.hasPath ps filename))
        (.inputFile fs (.hasAbsolutePath ps abs))
        (let [needle (str "/" filename)]
          (->> (.inputFiles fs (.all ps))
               (filter #(str/ends-with? (str (.path ^org.sonar.api.batch.fs.InputFile %)) needle))
               first)))))
