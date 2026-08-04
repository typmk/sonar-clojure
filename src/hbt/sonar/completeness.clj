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
  than of the build log.

  What counts as an input is `hbt.sonar.report/inputs`, the same table the
  sensors read and the properties are defined from. Keeping a second list here
  is how the check would come to disagree with the thing it checks."
  (:require [clojure.string :as str]
            [hbt.sonar.report :as report]))

(defn assess
  "present? is a predicate on a report entry. Returns the completeness report."
  [present?]
  (let [checked (map #(assoc % :present? (boolean (present? %))) report/inputs)
        missing (remove :present? checked)
        total   (count checked)
        present (- total (count missing))]
    {:checked checked
     :missing missing
     :total   total
     :present present
     ;; A percentage, so it can carry a quality-gate condition. 100 means every
     ;; input the plugin knows how to read was there.
     :percent (double (* 100 (/ present (max 1 total))))}))

(defn message
  "One line naming what is missing and what that costs, for the project issue."
  [{:keys [missing total present]}]
  (str present " of " total " analysis inputs present. Missing: "
       (str/join "; " (map #(str (:label %) " (" (:costs %) ")") missing))
       ". Until these are produced the dashboard cannot distinguish a clean"
       " project from an unmeasured one."))
