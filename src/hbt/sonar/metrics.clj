(ns hbt.sonar.metrics
  "Size and complexity measures over the parsed tree.

  Every Sonar ratio -- comment density, duplication density, technical-debt
  ratio -- divides by ncloc. Without these the dashboard reports a project
  with no code and every ratio is undefined."
  (:require [clojure.string :as str]
            [hbt.sonar.parse :as parse]))

(defn- line-span [{:keys [line end-line]}] (range line (inc end-line)))

(defn from-nodes
  "Measures over an already-parsed node stream, so a caller needing the nodes
  for other purposes parses once."
  [nodes]
  (let [leaves    (parse/leaves nodes)
        code      (into #{} (comp (remove :commented?)
                                  (remove #(contains? #{:comment :trivia} (:type %)))
                                  (mapcat line-span))
                        leaves)
        ;; `;` comments, `#_` forms and `(comment ...)` bodies all count
        commented (into #{} (comp (filter #(or (:commented? %) (= :comment (:type %))))
                                  (remove #(= :trivia (:type %)))
                                  (mapcat line-span))
                        leaves)
        ;; commented-out code is not code: a `#_`-ed defn is not a function,
        ;; and an `(if ...)` inside `(comment ...)` decides nothing
        live      (remove :commented? nodes)
        branches  (filter :branch? live)]
    {:ncloc         (count code)
     ;; a line carrying code and a trailing comment counts once, as code
     :comment-lines (count (remove code commented))
     :functions     (count (filter :function? live))
     :classes       (count (filter :class? live))
     ;; a statement is an invocation: in a Lisp that is every list form
     :statements    (count (filter #(= :list (:tag %)) live))
     :complexity    (inc (count branches))
     ;; nesting-weighted, as Sonar defines cognitive complexity: a branch
     ;; inside two branches costs three, not one
     :cognitive     (reduce + 0 (map #(inc (:branch-nesting %)) branches))}))

(defn- line-map
  "Sonar's per-line data format: \"1=1;2=0;3=1\"."
  [lines all]
  (->> (sort all)
       (map #(str % "=" (if (contains? lines %) 1 0)))
       (str/join ";")))

(defn line-data
  "The two per-line maps Sonar needs to reason about *which* lines matter.

  `ncloc-data` marks code lines; `executable-lines-data` marks lines that
  could have been covered. New-code coverage is computed against the
  executable set, so without it the number the quality gate tests is derived
  from whatever the coverage report happened to mention."
  [nodes]
  (let [leaves (parse/leaves nodes)
        code   (into #{} (comp (remove :commented?)
                               (remove #(contains? #{:comment :trivia} (:type %)))
                               (mapcat line-span))
                     leaves)
        ;; A line is executable if a live list form starts on it. A vector of
        ;; bindings or a bare symbol is code but nothing to execute, and
        ;; counting it would understate coverage against lines no test could
        ;; ever hit.
        exec   (into #{} (comp (remove :commented?)
                               (filter #(= :list (:tag %)))
                               (map :line))
                     nodes)
        span   (into code exec)]
    {:ncloc-data      (line-map code span)
     :executable-data (line-map exec span)}))

(defn measures
  "Measures for a source string, or nil when it does not parse."
  [source]
  (let [{:keys [ok? nodes]} (parse/parse source)]
    (when ok? (from-nodes nodes))))

(defn measures-of-file [f]
  (measures (slurp f)))
