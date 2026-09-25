(ns net.typemark.sonar.coverage
  "cloverage's codecov.json as data: read, and matched against a source path.

  codecov.json is the only cloverage output that keeps PARTIAL line coverage.
  The lcov writer emits `DA:<line>,<covered-form-count>`, so a line where one
  form of five ran reads as covered -- measured on this project, 22 of 451
  instrumented lines. lcov is therefore not read at all: a number known to be
  optimistic is worse than a missing one, which the completeness check names.

  Per line codecov.json holds:
    null    blank or not instrumented
    number  fully covered, value is the hit count
    true    PARTIALLY covered -- some forms ran, some did not
    0       instrumented, never run
  The array is positional and its first element is always null, so index 1
  is line 1.

  Two sensors read it -- the coverage sensor saves the hits, the source
  sensor takes the instrumented lines as its executable-lines truth."
  (:require [clojure.data.json :as json]
            [clojure.string :as str]))

(set! *warn-on-reflection* true)

(defn parse
  "codecov JSON -> {filename {line {:hits n :partial? bool}}}, or nil when the
  text is not codecov JSON."
  [text]
  (when-not (str/blank? text)
    (let [doc  (try (json/read-str text) (catch Exception _ nil))
          root (when (map? doc) (get doc "coverage" doc))]
      (when (map? root)
        (into {}
              (for [[file lines] root
                    :when (sequential? lines)]
                [file
                 (into {}
                       (keep-indexed
                        (fn [idx v]
                          (cond
                            (true? v)   [idx {:hits 1 :partial? true}]
                            (number? v) [idx {:hits (long v) :partial? false}]
                            :else       nil))
                        lines))]))))))

(defn instrumented-lines
  "The lines cloverage actually tracked, per file: ground truth for Sonar's
  executable-lines data, better than any heuristic over the parse tree."
  [parsed]
  (into {} (for [[f lines] parsed] [f (set (keys lines))])))

(defn lines-for
  "The entry of `by-path` for source path `p`. The report's key may or may
  not carry the source root, so an exact key wins, then a key that ends `p`
  at a path separator."
  [by-path ^String p]
  (or (get by-path p)
      (some (fn [[k v]] (when (str/ends-with? p (str "/" k)) v)) by-path)))
