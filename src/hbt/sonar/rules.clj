(ns hbt.sonar.rules
  "The rule catalogue. Generated from clj-kondo's default config at build
  time (see hbt.sonar.gen), so the two cannot drift silently."
  (:require [clojure.edn :as edn]
            [clojure.string :as string]
            [clojure.java.io :as io]
            [hbt.sonar.const :as const]
            [hbt.sonar.security :as security])
  (:import [org.sonar.api.rules CleanCodeAttribute RuleType]
           [org.sonar.api.server.rule RuleDescriptionSection]
           [org.sonar.api.server.rule RulesDefinition$OwaspTop10 RulesDefinition$OwaspTop10Version]
           [org.sonar.api.issue.impact Severity SoftwareQuality])
  (:gen-class
   :name hbt.sonar.ClojureRulesDefinition
   :implements [org.sonar.api.server.rule.RulesDefinition]))

(defn catalogue []
  (with-open [r (io/reader (io/resource "hbt/sonar/linters.edn"))]
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

(defn- security-description [{:keys [doc cwe]}]
  (str doc "<p>CWE: "
       (string/join ", "
         (map #(str "<a href=\"https://cwe.mitre.org/data/definitions/" % ".html\">CWE-" % "</a>") cwe))
       "</p>"))

(defn- add-security-rule!
  "Security rules carry their CWE and OWASP category, which is what Sonar's
  security reports are built from -- so the data is present the day the
  edition that renders it is licensed, rather than needing a rewrite then.

  A hotspot is a thing to review, not a thing known to be wrong. Sonar
  reviews the two separately, and mixing them makes both easier to ignore."
  [repo {:keys [key name hotspot? cwe owasp severity fix] :as r}]
  (let [rule (doto (with-debt! (.createRule repo key) severity)
               (.setName name)
               (.setHtmlDescription (security-description r))
               ;; Structured sections are what Sonar renders as the
               ;; "why is this an issue" / "how can I fix it" tabs. A single
               ;; blob of HTML renders as neither.
               (.addDescriptionSection (section "root_cause" (:doc r)))
               (.addDescriptionSection
                 (section "how_to_fix" (or fix "<p>Remove the unsafe call or move the value out of the caller's control.</p>")))
               (.setType (if hotspot?
                           RuleType/SECURITY_HOTSPOT
                           RuleType/VULNERABILITY))
               (.setCleanCodeAttribute CleanCodeAttribute/COMPLETE)
               (.setActivatedByDefault true)
               (.addTags (into-array String ["security" "cwe"])))]
    (when (seq cwe)
      (.addCwe rule (int-array cwe)))
    (when (seq owasp)
      (.addOwaspTop10 rule RulesDefinition$OwaspTop10Version/Y2021
                      (into-array RulesDefinition$OwaspTop10
                                  (map #(RulesDefinition$OwaspTop10/valueOf %) owasp))))
    ;; a hotspot has nothing to impact -- it is not yet known to be a defect
    (when-not hotspot?
      (.addDefaultImpact rule SoftwareQuality/SECURITY
                         (Severity/valueOf ^String severity)))
    rule))

(defn -define [_ ctx]
  (let [repo (-> (.createRepository ctx const/repository-key const/language-key)
                 (.setName "clj-kondo"))]
    (run! #(add-rule! repo %) (catalogue))
    (run! #(add-security-rule! repo %) security/rules)
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
