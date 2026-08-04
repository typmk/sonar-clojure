(ns hbt.sonar.codecov
  "Reads cloverage's codecov.json, which is the only cloverage output that
  preserves PARTIAL line coverage.

  Why not lcov: its reporter writes `DA:<line>,<covered-form-count>`, so a
  line where one form of five was exercised emits `DA:42,1` and Sonar records
  the line as covered. Partial coverage is silently rounded up and the number
  the quality gate tests comes out optimistic.

  codecov.json keeps the distinction. Per line it holds:
    null    blank or not instrumented
    number  fully covered, value is the hit count
    true    PARTIALLY covered -- some forms ran, some did not
    0       instrumented, never run
  The array is positional and its first element is always null, so index 1
  is line 1."
  (:require [clojure.data.json :as json]
            [clojure.string :as str]))

(defn parse
  "codecov JSON -> {filename {line {:hits n :partial? bool}}}."
  [text]
  (when-not (str/blank? text)
    (let [root (get (json/read-str text) "coverage" (json/read-str text))]
      (into {}
            (for [[file lines] root
                  :when (sequential? lines)]
              [file
               (into {}
                     (keep-indexed
                      (fn [idx v]
                        (cond
                          (nil? v)         nil
                          (true? v)        [idx {:hits 1 :partial? true}]
                          (false? v)       nil
                          (number? v)      [idx {:hits (long v) :partial? false}]
                          :else            nil))
                      lines))])))))

(defn instrumented-lines
  "The lines cloverage actually tracked, per file. This is ground truth for
  Sonar's executable-lines data -- better than any heuristic over the parse
  tree, because it is what the coverage tool itself measured."
  [parsed]
  (into {} (for [[f lines] parsed] [f (set (keys lines))])))

(defn summary [parsed]
  {:files   (count parsed)
   :lines   (reduce + 0 (map count (vals parsed)))
   :covered (reduce + 0 (map (fn [m] (count (filter #(pos? (:hits %)) (vals m)))) (vals parsed)))
   :partial (reduce + 0 (map (fn [m] (count (filter :partial? (vals m)))) (vals parsed)))})
