(ns au.com.heisenbergtech.sonar.external
  "Findings from analyzers other than clj-kondo, imported as ad-hoc rules.

  An ad-hoc rule is declared at scan time rather than registered on the
  server, so splint, eastwood, clj-holmes and nvd-clojure can contribute
  without this plugin carrying a copy of their rule catalogues -- which it
  would then have to keep in step with four separate release cycles.

  The cost is that ad-hoc rules do not appear in quality profiles and cannot
  be switched off from the Sonar UI. That is the correct trade: each of those
  tools already has its own config file, and having two places to disable a
  rule is worse than having one."
  (:require [clojure.data.json :as json]
            [clojure.string :as str]))

(def engines
  "Each external analyzer, and how to read what it emits.

  splint and clj-holmes both emit clj-kondo-shaped JSON (`findings` with
  filename/row/col/level/type/message), which is why one reader serves both."
  {"splint"      {:name "splint" :quality "MAINTAINABILITY" :type "CODE_SMELL"}
   "clj-holmes"  {:name "clj-holmes" :quality "SECURITY" :type "VULNERABILITY"}
   "eastwood"    {:name "eastwood" :quality "RELIABILITY" :type "BUG"}
   "nvd"         {:name "nvd-clojure" :quality "SECURITY" :type "VULNERABILITY"}})

(def ^:private severity
  {"error" "HIGH" "warning" "MEDIUM" "info" "LOW"})

(defn findings
  "Report text -> normalised findings tagged with their engine.

  Accepts the clj-kondo JSON shape, which splint and clj-holmes both emit.
  Anything else yields nothing rather than a guess -- a misparsed report that
  silently produces zero findings is the failure this plugin exists to stop,
  so the caller reports the count and a zero is visible."
  [engine-id text]
  (when-not (str/blank? text)
    (let [parsed (try (json/read-str text) (catch Exception _ nil))
          fs     (get parsed "findings")]
      (when (sequential? fs)
        (vec
         (for [f fs
               :let [file (get f "filename") row (get f "row")]
               :when (and file row)]
           {:engine   engine-id
            :rule     (or (get f "type") "finding")
            :filename file
            :line     (max 1 (long row))
            :col      (max 1 (long (or (get f "col") 1)))
            :end-line (long (or (get f "end-row") row))
            :end-col  (long (or (get f "end-col") (inc (or (get f "col") 1))))
            :severity (get severity (get f "level") "MEDIUM")
            :message  (or (get f "message") "")}))))))

(defn rule-ids
  "The distinct (engine, rule) pairs a report mentions -- each needs an
  ad-hoc rule declared before its issues can be saved."
  [findings]
  (into #{} (map (juxt :engine :rule)) findings))
