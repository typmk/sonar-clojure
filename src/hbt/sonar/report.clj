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
    (for [p (if (seq given) given [default])]
      (let [f (io/file p)]
        (if (.isAbsolute f) f (io/file base p))))))

(defn exists? [^File f] (.isFile f))

(defn input-file
  "The InputFile for a path named inside a report, or nil.

  Tools emit paths relative to their own working directory while Sonar
  indexes relative to the module base, so try the relative path first and the
  base-resolved absolute path second."
  [ctx ^String filename]
  (let [fs  (.fileSystem ctx)
        ps  (.predicates fs)
        abs (.getAbsolutePath (io/file (.baseDir fs) filename))]
    (or (.inputFile fs (.hasPath ps filename))
        (.inputFile fs (.hasAbsolutePath ps abs)))))
