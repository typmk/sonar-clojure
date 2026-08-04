(ns hbt.sonar.rules
  "The rule catalogue. Generated from clj-kondo's default config at build
  time (see hbt.sonar.gen), so the two cannot drift silently."
  (:require [clojure.edn :as edn]
            [hbt.sonar.classpath :as classpath]
            [clojure.java.io :as io]
            [hbt.sonar.const :as const]
            [hbt.sonar.concurrency :as concurrency]
            [hbt.sonar.interop :as interop]
            [hbt.sonar.metadata :as metadata]
            [hbt.sonar.security :as security])
  (:import [org.sonar.api.rules CleanCodeAttribute RuleType]
           [org.sonar.api.server.rule RuleDescriptionSection]
           [org.sonar.api.server.rule RulesDefinition$OwaspTop10 RulesDefinition$OwaspTop10Version]
           [org.sonar.api.issue.impact Severity SoftwareQuality])
  (:gen-class
   :name hbt.sonar.ClojureRulesDefinition
   :implements [org.sonar.api.server.rule.RulesDefinition]))

(defn catalogue []
  (with-open [r (io/reader (classpath/required-resource
                             "hbt/sonar/linters.edn"
                             "Run `clojure -X:gen-rules` and rebuild."))]
    (edn/read (java.io.PushbackReader. r))))

(def ^:private remediation
  "Minutes to fix, by impact severity. Without a remediation function every
  rule costs nothing, `sqale_index` is 0 and the maintainability rating is
  computed from an empty set -- your PHP project reports 15,384 minutes of
  debt, Clojure reported none."
  {"HIGH" "30min" "MEDIUM" "10min" "LOW" "5min"})

(defn- section [key html]
  (-> (RuleDescriptionSection/builder)
      (.sectionKey key)
      (.htmlContent html)
      (.build)))

(defn- description [{:keys [key url]}]
  (str "<p>clj-kondo linter <code>" key "</code>.</p>"
       "<p>Configure it in <code>.clj-kondo/config.edn</code> under "
       "<code>{:linters {:" key " {:level ...}}}</code>.</p>"
       "<p><a href=\"" url "\">Linter documentation</a></p>"))

(defn- with-debt!
  "Minutes to fix. Set on the rule, which is where the API keeps it."
  [rule severity]
  (.setDebtRemediationFunction
    rule (.constantPerIssue (.debtRemediationFunctions rule)
                            (get remediation severity "10min")))
  rule)

(defn- add-rule!
  "The catalogue names Sonar's enums directly, so this reads them rather than
  translating through a table that would have to be kept in step."
  [repo r]
  (doto (with-debt! (.createRule repo (:key r)) (:severity r))
    (.setName (:name r))
    (.setHtmlDescription (description r))
    (.setType (RuleType/valueOf ^String (:type r)))
    (.setCleanCodeAttribute (CleanCodeAttribute/valueOf ^String (:attribute r)))
    (.addDefaultImpact (SoftwareQuality/valueOf ^String (:quality r))
                       (Severity/valueOf ^String (:severity r)))
    ;; clj-kondo's own default level decides membership of the shipped
    ;; profile: what it considers off by default stays off here.
    (.setActivatedByDefault (not= :off (:level r)))))

(defn- add-authored-rule!
  "A rule whose metadata ships as a resource pair, in SonarSource's own
  layout. Prose, severity, CWEs and remediation cost come from the JSON and
  HTML; nothing about the rule is stated twice."
  [repo {:keys [key name type html quality severity attribute hotspot?
                cwe owasp remediation tags]}]
  (let [rule (doto (.createRule repo key)
               (.setName name)
               (.setHtmlDescription html)
               (.addDescriptionSection (section "root_cause" html))
               (.setType (RuleType/valueOf ^String type))
               (.setActivatedByDefault true)
               (.addTags (into-array String tags)))]
    (.setDebtRemediationFunction
     rule (.constantPerIssue (.debtRemediationFunctions rule) remediation))
    (when (seq cwe) (.addCwe rule (int-array cwe)))
    (when (seq owasp)
      (.addOwaspTop10 rule RulesDefinition$OwaspTop10Version/Y2021
                      (into-array RulesDefinition$OwaspTop10
                                  (map #(RulesDefinition$OwaspTop10/valueOf %) owasp))))
    ;; a hotspot is outside the clean-code model: not yet known to be a defect
    (when-not hotspot?
      (.setCleanCodeAttribute rule (CleanCodeAttribute/valueOf ^String attribute))
      (.addDefaultImpact rule (SoftwareQuality/valueOf ^String quality)
                         (Severity/valueOf ^String severity)))
    rule))

(defn -define [_ ctx]
  (let [repo (-> (.createRepository ctx const/repository-key const/language-key)
                 (.setName "clj-kondo"))]
    (run! #(add-rule! repo %) (catalogue))
    ;; deduped by key: interop registers weak-hash-algorithm once even though
    ;; several classes raise it
    (run! #(add-authored-rule! repo %)
          (metadata/load-rules (concat security/rule-keys interop/rule-keys
                                       concurrency/rule-keys)))
    ;; The catch-all. A finding from a clj-kondo newer than this plugin must
    ;; surface as an issue, not vanish between the report and the dashboard.
    (doto (.createRule repo const/unknown-rule)
      (.setName "Unrecognised clj-kondo linter")
      (.setHtmlDescription
       (str "<p>clj-kondo reported a finding whose linter is not in this "
            "plugin's catalogue. The plugin was built against an older "
            "clj-kondo than the one that produced the report.</p>"
            "<p>Regenerate the catalogue: "
            "<code>clojure -X:gen-rules</code>, then rebuild.</p>"))
      (.setType RuleType/CODE_SMELL)
      (.setCleanCodeAttribute CleanCodeAttribute/CLEAR)
      (.addDefaultImpact SoftwareQuality/MAINTAINABILITY Severity/LOW)
      (.setActivatedByDefault true))
    (.done repo)
    nil))
