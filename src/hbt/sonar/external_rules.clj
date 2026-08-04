(ns hbt.sonar.external-rules
  "Rule repositories for the other Clojure analyzers, registered on the
  server rather than declared ad hoc at scan time.

  Ad-hoc rules were the first design here; upstream pre-registers instead.
  sonar-php ships `ExternalRuleLoader` from sonar-analyzer-commons and builds
  an `external_<linter>` repository from a shipped catalogue.

  To be accurate about what this buys, since I overstated it once: external
  issues never require quality-profile activation either way, so this is not
  about being able to switch rules off. What it buys is that all 121 splint
  rules are BROWSABLE in the Rules UI with names and descriptions before
  anyone has run splint even once -- rather than appearing one at a time,
  nameless, as findings happen to occur.

  A finding whose rule is not in the catalogue still reaches the dashboard as
  an ad-hoc rule: the same known/unknown split already used for clj-kondo's
  `unknown-linter`, not a second mechanism."
  (:require [clojure.data.json :as json]
            [hbt.sonar.classpath :as classpath]
            [hbt.sonar.const :as const]
            [hbt.sonar.external :as external])
  (:import [org.sonar.api.rules CleanCodeAttribute RuleType]
           [org.sonar.api.issue.impact Severity SoftwareQuality])
  (:gen-class
   :name hbt.sonar.ExternalRulesDefinition
   :implements [org.sonar.api.server.rule.RulesDefinition]))

(defn catalogue
  "The shipped rule list for one engine, or nil when none is shipped."
  [engine-id]
  (when-let [r (classpath/resource (str "org/sonar/l10n/clj/rules/external_" engine-id ".json"))]
    (json/read-str (slurp r) :key-fn keyword)))

(defn repository-key [engine-id] (str "external_" engine-id))

(defn- add! [repo {:keys [key name description type severity quality]}]
  (doto (.createRule repo key)
    (.setName (or name key))
    (.setHtmlDescription (or description "<p>Reported by the external analyzer.</p>"))
    (.setType (RuleType/valueOf ^String (or type "CODE_SMELL")))
    (.setCleanCodeAttribute CleanCodeAttribute/LOGICAL)
    (.addDefaultImpact (SoftwareQuality/valueOf ^String (or quality "MAINTAINABILITY"))
                       (Severity/valueOf ^String (or severity "MEDIUM")))
    (.setActivatedByDefault false)))

(defn -define [_ ctx]
  (doseq [[engine-id {:keys [name]}] external/engines
          :let [rules (catalogue engine-id)]
          :when (seq rules)]
    (let [repo (-> (.createRepository ctx (repository-key engine-id) const/language-key)
                   (.setName name))]
      (run! #(add! repo %) rules)
      (.done repo)))
  nil)
