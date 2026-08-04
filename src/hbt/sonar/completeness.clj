(ns hbt.sonar.completeness
  "Whether the analysis actually had its inputs.

  This plugin reads reports it does not produce. When one is absent the
  dashboard does not go blank -- it goes GREEN. No clj-kondo report reads as
  zero issues; no coverage report reads as 0%, which then fails the gate for a
  reason unrelated to the tests. Both are indistinguishable, on the dashboard,
  from a project that was measured and found clean.

  Every sensor already says so on stdout. Nobody reads scanner logs.

  So completeness becomes data in its own right: a metric with a percentage,
  and a project-level issue naming each missing input. A reviewer can then ask
  the question that matters -- was this measured? -- of the dashboard rather
  than of the build log."
  (:require [clojure.string :as str]
            [hbt.sonar.const :as const]))

(def expected
  "Every report the plugin reads, and what its absence costs. Ordered by how
  misleading the silence is."
  [{:key :kondo    :prop const/report-paths-prop   :default const/default-report
    :label "clj-kondo findings"
    :costs "no rule findings at all -- the project reads as having zero issues"}
   {:key :coverage :prop const/coverage-paths-prop :default const/default-coverage
    :label "cloverage coverage"
    :costs "coverage reports as 0%, failing the quality gate for a reason unrelated to the tests"}
   {:key :analysis :prop const/analysis-paths-prop :default const/default-analysis
    :label "clj-kondo analysis"
    :costs "no symbol navigation, no dictionary check, no interprocedural taint"}
   {:key :tests    :prop const/test-report-paths-prop :default const/default-test-report
    :label "kaocha test execution"
    :costs "no test counts; coverage is the only evidence the code is exercised"}])

(defn assess
  "present? is a predicate on an entry. Returns the completeness report."
  [present?]
  (let [checked (map #(assoc % :present? (boolean (present? %))) expected)
        missing (remove :present? checked)]
    {:checked checked
     :missing missing
     :total (count checked)
     :present (- (count checked) (count missing))
     ;; A percentage, so it can carry a quality-gate condition. 100 means every
     ;; input the plugin knows how to read was there.
     :percent (double (* 100 (/ (- (count checked) (count missing))
                                (max 1 (count checked)))))}))

(defn message
  "One line naming what is missing and what that costs, for the project issue."
  [{:keys [missing total present]}]
  (str present " of " total " analysis inputs present. Missing: "
       (str/join
        "; "
        (map #(str (:label %) " (" (:costs %) ")") missing))
       ". Until these are produced the dashboard cannot distinguish a clean"
       " project from an unmeasured one."))
