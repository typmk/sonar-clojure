(ns net.typemark.sonar.external
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
  filename/row/col/level/type/message), which is why one reader serves both.
  opengrep emits SARIF, read by shape rather than by engine name so any other
  SARIF-emitting tool can be pointed at the same property."
  {"splint"      {:name "splint" :quality "MAINTAINABILITY" :type "CODE_SMELL"}
   "clj-holmes"  {:name "clj-holmes" :quality "SECURITY" :type "VULNERABILITY"}
   "eastwood"    {:name "eastwood" :quality "RELIABILITY" :type "BUG"}
   "nvd"         {:name "nvd-clojure" :quality "SECURITY" :type "VULNERABILITY"}
   "opengrep"    {:name "opengrep" :quality "SECURITY" :type "VULNERABILITY"}})

(def ^:private severity
  "clj-kondo levels and SARIF levels, which overlap but are not the same set."
  {"error" "HIGH" "warning" "MEDIUM" "info" "LOW"
   "note" "LOW" "none" "INFO"})

(defn- short-rule-id
  "opengrep derives a rule's SARIF id from the path its config was loaded
  from, so `-f /home/me/proj/opengrep/taint.yml` yields
  `home.me.proj.opengrep.clj-sql-injection`. That id embeds an absolute path:
  it differs between a developer's machine and CI, so the same finding arrives
  under two different rule keys and Sonar cannot track it as one issue.

  The last dotted segment is the rule's own name and is stable. Registry rules
  like `python.lang.security.audit.eval-detected` lose their category prefix,
  which costs some context and buys a key that means the same thing
  everywhere; for ad-hoc rules, which carry their engine name separately and
  never appear in a quality profile, that is the better trade."
  [^String id]
  (if (str/blank? id) "finding" (last (str/split id #"\."))))

(defn- sarif-findings
  "SARIF 2.1.0 -> normalised findings.

  Severity is NOT on the result: SARIF carries it as defaultConfiguration.level
  on the rule, so the rules array has to be indexed first. Reading level off
  the result yields nil for every finding and silently flattens the report to
  one severity."
  [engine-id parsed]
  (vec
   (for [run (get parsed "runs")
         :let [levels (into {} (for [r (get-in run ["tool" "driver" "rules"])]
                                 [(get r "id") (get-in r ["defaultConfiguration" "level"])]))]
         res (get run "results")
         :let [loc (get-in res ["locations" 0 "physicalLocation"])
               file (get-in loc ["artifactLocation" "uri"])
               reg (get loc "region")
               line (get reg "startLine")]
         :when (and file line)]
     {:engine   engine-id
      :rule     (short-rule-id (get res "ruleId"))
      :filename file
      :line     (max 1 (long line))
      :col      (max 1 (long (or (get reg "startColumn") 1)))
      :end-line (long (or (get reg "endLine") line))
      :end-col  (long (or (get reg "endColumn") (inc (or (get reg "startColumn") 1))))
      :severity (get severity (or (get res "level") (get levels (get res "ruleId"))) "MEDIUM")
      :message  (or (get-in res ["message" "text"]) "")})))

(defn findings
  "Report text -> normalised findings tagged with their engine.

  Accepts the clj-kondo JSON shape, which splint and clj-holmes both emit, and
  SARIF, which opengrep emits. Dispatched on the shape of the report rather
  than the name of the engine, so a tool that changes format is read correctly
  and a tool that emits SARIF needs no code here at all.

  Anything else yields nothing rather than a guess -- a misparsed report that
  silently produces zero findings is the failure this plugin exists to stop,
  so the caller reports the count and a zero is visible."
  [engine-id text]
  (when-not (str/blank? text)
    (let [parsed (try (json/read-str text) (catch Exception _ nil))
          fs     (get parsed "findings")]
      (if (sequential? (get parsed "runs"))
        (sarif-findings engine-id parsed)
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
            :message  (or (get f "message") "")})))))))

(defn rule-ids
  "The distinct (engine, rule) pairs a report mentions -- each needs an
  ad-hoc rule declared before its issues can be saved."
  [findings]
  (into #{} (map (juxt :engine :rule)) findings))
