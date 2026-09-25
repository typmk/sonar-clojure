(ns net.typemark.sonar.coverage
  "A cloverage report as data: read, and matched against a source path.

  Two sensors read it -- the coverage sensor saves the hits, the source
  sensor takes the instrumented lines as its executable-lines truth -- so the
  reading lives here, where neither needs the other's gen-class to get it."
  (:require [clojure.string :as str]
            [net.typemark.sonar.codecov :as codecov]
            [net.typemark.sonar.lcov :as lcov])
  (:import [java.io File]))

(set! *warn-on-reflection* true)

(defn codecov? [^File f] (str/ends-with? (.getName f) ".json"))

(defn read-report
  "Both formats normalise to {file {line {:hits n :partial? bool}}}."
  [^File f]
  (if (codecov? f)
    (codecov/parse (slurp f))
    (into {} (for [[file lines] (lcov/parse (slurp f))]
               [file (into {} (for [[l h] lines] [l {:hits h :partial? false}]))]))))

(defn lines-for
  "The entry of `by-path` for source path `p`. The report's key may or may
  not carry the source root -- cloverage's two writers disagree -- so an exact
  key wins, then a key that ends `p` at a path separator."
  [by-path ^String p]
  (or (get by-path p)
      (some (fn [[k v]] (when (str/ends-with? p (str "/" k)) v)) by-path)))
