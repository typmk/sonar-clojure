(ns score
  "Scores an analyzer against the corpus.

  Reports recall (of the weaknesses planted, how many were found) and
  precision (of the findings raised, how many were real). Both, always: a rule
  that fires on everything has perfect recall, and a rule that never fires has
  perfect precision. Either alone is a number you can game without noticing.

  Run:
    opengrep scan --taint-intrafile -f opengrep/clojure-taint.yml \\
      --sarif-output=target/corpus.sarif corpus/cases
    clojure -M:corpus target/corpus.sarif

  Exits non-zero when a case regresses, so this can gate."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [net.typemark.sonar.external :as external]
            [net.typemark.sonar.kondo :as kondo]
            [net.typemark.sift :as sift]))

(defn- manifest [] (edn/read-string (slurp (io/file "corpus" "manifest.edn"))))

(defn- key-for
  "Manifest keys are paths relative to corpus/cases, so a case in a
  subdirectory keeps its directory. Matching on basename alone would make
  xfile/handler.clj and handler.clj the same case."
  [path]
  (let [p (str/replace path #"^.*corpus/cases/" "")]
    (if (str/includes? p "/") p (last (str/split p #"/")))))

(defn- tally [findings]
  (reduce (fn [acc {:keys [filename rule]}]
            (update acc (key-for filename) (fnil conj #{}) rule))
          {} findings))

(defn- kondo-findings
  "clj-kondo's own JSON, for the hook rules. Their findings never reach this
  plugin's Clojure at all -- they arrive through the report -- so nothing in
  the suite could name them. The key is kondo/hook-rule's, the one a finding
  reaches Sonar under."
  [json-path]
  (tally (for [f (external/findings "clj-kondo" (slurp json-path))
               :let [rule (kondo/hook-rule (:rule f))]
               :when rule]
           (assoc f :rule rule))))

(defn- opengrep-findings [sarif-path]
  (tally (external/findings "opengrep" (slurp sarif-path))))

(defn- callgraph-findings
  "This plugin's own interprocedural pass, over clj-kondo's whole-project
  analysis. It is the only engine here that crosses a file boundary, which is
  the shape that dominates real code -- measured across lume, sur and forma,
  26 files hold a source and 46 hold a sink while only 4 hold both.

  Seeded from the same per-file scan the sensor uses, so this measures what
  actually ships rather than a bench rig."
  [analysis-path]
  (let [files (->> (file-seq (io/file "corpus" "cases"))
                   (filter #(str/ends-with? (.getName %) ".clj")))
        linter (sift/linter {:rulesets #{}
                             :rules {:security/interprocedural-taint :warning}
                             :kondo (slurp analysis-path)})]
    (tally (for [f (:findings (sift/lint linter (for [f files] {:path (str f) :text (slurp f)})))]
             {:filename (:file f) :rule (name (:rule f))}))))

(defn score
  "engine defaults to opengrep; :known-miss entries for that engine are still
  counted as misses in recall and do NOT fail the gate.

  A failing case deleted stops being evidence, and a failing case that blocks
  every build gets deleted. Recording the miss keeps the number honest and the
  gate useful: recall says what the engine cannot do, regressions say whether
  it got worse."
  ([report] (score report "opengrep"))
  ([report engine]
  ;; Rule-level for opengrep, whose vocabulary the manifest is written in;
  ;; file-level for anything else. The callgraph reports one rule --
  ;; `interprocedural-taint` -- for every weakness class, so comparing its rule
  ;; names against clj-sql-injection would score it 0 for finding exactly the
  ;; thing it was built to find. Different engines name the same weakness
  ;; differently, and the question being asked is whether the file was caught.
  (let [rule-level? (= engine "opengrep")
        found (case engine
                "opengrep"  (opengrep-findings report)
                "callgraph" (callgraph-findings report)
                "kondo"     (kondo-findings report)
                ;; The union, and the only mode worth gating. No engine here
                ;; is the answer alone: opengrep sees taint within a file, the
                ;; callgraph sees it across files, and the clj-kondo hooks see
                ;; the crypto and interop weaknesses that need a resolved var
                ;; rather than dataflow. Scoring any one of them against the
                ;; whole manifest marks it failed for not doing another's job.
                "union" (merge-with into
                                    (opengrep-findings (str report ".sarif"))
                                    (callgraph-findings (str report ".json"))
                                    (kondo-findings (str report "-kondo.json"))))
        rows  (for [{:keys [file expect cwe why known-miss]} (manifest)
                    :let [got (get found file #{})
                          tp  (if rule-level?
                                (count (filter got expect))
                                (if (and (seq expect) (seq got)) (count expect) 0))
                          fn' (if rule-level?
                                (count (remove got expect))
                                (if (and (seq expect) (empty? got)) (count expect) 0))
                          fp  (if rule-level?
                                (count (remove expect got))
                                (if (and (empty? expect) (seq got)) (count got) 0))
                          known (get known-miss engine)]]
                {:file file :cwe cwe :why why :expect expect :got got
                 :known known
                 :tp tp :fn fn' :fp fp
                 :ok? (and (zero? fp) (or (zero? fn') (some? known)))})
        tp (reduce + (map :tp rows))
        fn' (reduce + (map :fn rows))
        fp (reduce + (map :fp rows))
        pct (fn [n d] (if (zero? d) 100.0 (double (* 100 (/ n d)))))]
    {:rows rows :tp tp :fn fn' :fp fp
     :recall (pct tp (+ tp fn'))
     :precision (pct tp (+ tp fp))
     :cases (count rows)
     :known (count (filter :known rows))
     :failed (remove :ok? rows)})))

(defn -main [& [report engine]]
  (let [engine (or engine "opengrep")
        path (or report "target/combined")]
    (doseq [needed (if (= engine "union")
                     [(str path ".sarif") (str path ".json") (str path "-kondo.json")]
                     [path])]
      (when-not (.isFile (io/file needed))
        (println "no report at" needed "-- see corpus/README.md")
        (System/exit 2)))
    (println "engine:" engine)
    (let [{:keys [rows tp fp recall precision cases failed] :as s} (score path engine)
          misses (:fn s)]
      (println (format "%-28s %-22s %s" "CASE" "EXPECTED" "GOT"))
      (doseq [{:keys [file expect got ok? known]} rows]
        (println (format "%-2s %-25s %-22s %s"
                         (cond known "--" ok? "ok" :else "XX") file
                         (if (seq expect) (str/join "," expect) "(none)")
                         (if (seq got) (str/join "," got) "(none)"))))
      (println)
      ;; `misses`, not a :keys binding: {:keys [fn']} destructures :fn', not
      ;; :fn, so the count printed 0 next to a recall that said otherwise.
      (println (format "cases %d   TP %d   FN %d   FP %d" cases tp misses fp))
      (println (format "recall %.1f%%   precision %.1f%%" recall precision))
      (println (format "%d case(s) marked known-miss: counted in recall, not gated"
                       (:known s)))
      (doseq [{:keys [file known]} (filter :known rows)]
        (println "  --" file)
        (println "     " (str/replace known #"\s+" " ")))
      (when (seq failed)
        (println)
        (doseq [{:keys [file why expect got]} failed]
          (println "FAILED" file)
          (println "  expected:" (or (seq expect) "(none)") " got:" (or (seq got) "(none)"))
          (println "  why this case exists:" (str/replace why #"\s+" " "))))
      (System/exit (if (seq failed) 1 0)))))
