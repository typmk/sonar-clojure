(ns net.typemark.sonar.report
  "Locating a report on disk, and matching a path inside it to a file Sonar
  indexed.

  Both sensors and the symbol loader had their own copy of this. It is the
  code path where a mistake means findings silently disappear between the
  linter and the dashboard, so it exists once.

  WHICH reports get read is `net.typemark.sonar.inputs`."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [net.typemark.sonar.inputs :as inputs])
  (:import [java.io File]))

(set! *warn-on-reflection* true)

(defn paths
  "The configured report paths for `prop`, or `default` when unset, each
  resolved against the module base unless already absolute."
  [ctx prop default]
  (let [base  (.baseDir (.fileSystem ctx))
        given (remove str/blank? (.getStringArray (.config ctx) prop))]
    (for [p (if (seq given) given (if default [default] []))]
      (let [f (io/file p)]
        (if (.isAbsolute f) f (io/file base p))))))

(defn for-input
  "The paths configured for a registered report, by id. Preferred over `paths`:
  it makes the property and its default impossible to mispair."
  [ctx id]
  (let [{:keys [prop default]} (inputs/input id)]
    (paths ctx prop default)))

(defn exists? [^File f] (.isFile f))

(defn- holds?
  "Whether `f` contains `needle`, scanned as a stream: an analysis report runs
  to tens of megabytes, and presence is all that is asked."
  [^File f ^String needle]
  (with-open [s (java.util.Scanner. f "UTF-8")]
    (some? (.findWithinHorizon s (java.util.regex.Pattern/quote needle) 0))))

(defn present?
  "Whether a registered report is on disk, at a configured or default path,
  and -- for an input that shares its file with another -- carries its part.
  The analysis defaults to the findings report, and a findings-only report
  there must read as missing analysis, not as complete."
  [ctx id]
  (let [{:keys [holds]} (inputs/input id)]
    (boolean (some #(and (exists? %) (or (nil? holds) (holds? % holds)))
                   (for-input ctx id)))))

(defn input-file
  "The InputFile for a path named inside a report, or nil.

  Three attempts, because the tools disagree about what a path is relative
  to. cloverage's lcov writes `src/net/typemark/sonar/x.clj` while its codecov writer
  drops the source root and writes `net/typemark/sonar/x.clj`; clj-kondo writes
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
