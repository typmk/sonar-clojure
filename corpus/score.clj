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
            [au.com.heisenbergtech.sonar.external :as external]))

(defn- manifest [] (edn/read-string (slurp (io/file "corpus" "manifest.edn"))))

(defn- by-file
  "SARIF -> {basename #{rule ...}}. Basenames, because the scanner is run from
  the project root and the paths in the report are relative to it."
  [sarif-path]
  (reduce (fn [acc {:keys [filename rule]}]
            (update acc (last (str/split filename #"/")) (fnil conj #{}) rule))
          {}
          (external/findings "opengrep" (slurp sarif-path))))

(defn score
  "engine defaults to opengrep; :known-miss entries for that engine are still
  counted as misses in recall and do NOT fail the gate.

  A failing case deleted stops being evidence, and a failing case that blocks
  every build gets deleted. Recording the miss keeps the number honest and the
  gate useful: recall says what the engine cannot do, regressions say whether
  it got worse."
  ([sarif-path] (score sarif-path "opengrep"))
  ([sarif-path engine]
  (let [found (by-file sarif-path)
        rows  (for [{:keys [file expect cwe why known-miss]} (manifest)
                    :let [got (get found file #{})
                          tp  (count (filter got expect))
                          fn' (count (remove got expect))
                          fp  (count (remove expect got))
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

(defn -main [& [sarif-path]]
  (let [path (or sarif-path "target/corpus.sarif")]
    (when-not (.isFile (io/file path))
      (println "no report at" path "-- run opengrep first; see corpus/README.md")
      (System/exit 2))
    (let [{:keys [rows tp fp recall precision cases failed] :as s} (score path)
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
