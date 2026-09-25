(ns net.typemark.sonar.kondo-sensor
  "Reads a clj-kondo JSON report and saves one Sonar issue per finding.

  It reads a report rather than invoking clj-kondo: the scanner then needs no
  clj-kondo binary, and CI lints exactly once for both the local gate and the
  dashboard. One run, one set of findings, nothing to reconcile.

  Decisions live in net.typemark.sonar.kondo; this namespace is the container-facing
  shell and holds no logic that could be wrong without failing loudly."
  (:require [net.typemark.sonar.const :as const]
            [net.typemark.sonar.kondo :as kondo]
            [net.typemark.sonar.report :as report]
            [net.typemark.sonar.rules :as rules])
  (:import [java.io File]
           [org.sonar.api.batch.fs InputFile]
           [org.sonar.api.rule RuleKey]))

(set! *warn-on-reflection* true)

(defn- known-rules []
  (into #{const/unknown-rule} (map :key) (rules/catalogue)))

(defn- text-range [^InputFile f finding]
  (let [s (kondo/span finding)]
    (try
      (if (kondo/whole-line? s)
        (.selectLine f (:line s))
        (.newRange f (:line s) (:start-offset s) (:end-line s) (:end-offset s)))
      (catch Exception _
        (.selectLine f (:line s))))))

(defn- save-issue! [ctx known ^InputFile f finding]
  (let [{:keys [rule message recognised?]} (kondo/classify known finding)
        issue (.newIssue ctx)]
    (-> issue
        (.forRule (RuleKey/of const/repository-key rule))
        (.at (-> (.newLocation issue)
                 (.on f)
                 (.at (text-range f finding))
                 (.message message)))
        (.save))
    recognised?))

(defn- import-report! [ctx known ^File f]
  (let [tally (atom {:saved 0 :unmatched 0 :unrecognised 0})]
    (doseq [finding (kondo/findings (slurp f))]
      (if-let [in (report/input-file ctx (:filename finding))]
        (do (swap! tally update :saved inc)
            (when-not (save-issue! ctx known in finding)
              (swap! tally update :unrecognised inc)))
        (swap! tally update :unmatched inc)))
    (let [{:keys [saved unmatched unrecognised]} @tally]
      (println (format "clj-kondo %s: %d issues saved" (.getName f) saved))
      (when (pos? unmatched)
        (println (format "clj-kondo %s: %d findings dropped -- file not indexed by Sonar. Check sonar.sources and %s."
                         (.getName f) unmatched const/suffixes-prop)))
      (when (pos? unrecognised)
        (println (format "clj-kondo %s: %d findings from linters newer than this plugin. Regenerate: clojure -X:gen-rules"
                         (.getName f) unrecognised))))))

(defn execute! [ctx]
  (let [known (known-rules)]
    (report/each ctx :kondo #(import-report! ctx known %)))
  nil)
