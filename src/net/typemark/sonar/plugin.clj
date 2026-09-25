(ns net.typemark.sonar.plugin
  "Entry point named by Plugin-Class in the jar manifest."
  (:require [clojure.string :as str]
            [net.typemark.sonar.const :as const]
            [net.typemark.sonar.coverage-sensor]
            [net.typemark.sonar.language]
            [net.typemark.sonar.profile]
            [net.typemark.sonar.inputs :as inputs]
            [net.typemark.sonar.provenance :as provenance]
            [net.typemark.sonar.rules]
            [net.typemark.sonar.sensor]
            [net.typemark.sonar.source-sensor]
            [net.typemark.sonar.test-sensor]
            [net.typemark.sonar.external-sensor]
            [net.typemark.sonar.external-rules])
  (:import [org.sonar.api.config PropertyDefinition PropertyDefinition$ConfigScope])
  (:gen-class
   :name net.typemark.sonar.ClojurePlugin
   :implements [org.sonar.api.Plugin]))

(set! *warn-on-reflection* true)

(def ^:private property-specs
  "The two file-selection properties, plus one per report in the registry --
  which is where each report's key, default and prose already live."
  (concat
   [{:key     const/suffixes-prop
     :name    "File suffixes"
     :default (str/join "," const/default-suffixes)
     :doc     "Comma-separated file suffixes analysed as Clojure."}

    {:key     const/patterns-prop
     :name    "File patterns"
     :default (str/join "," (map #(str "**/*" %) const/default-suffixes))
     :doc     "Glob patterns analysed as Clojure. Read by the scanner's language detection."}]
   (for [{:keys [prop name default doc]} inputs/inputs]
     {:key prop :name name :default default :doc doc})))

(def ^:private external-property-specs
  (for [[engine prop] const/external-report-props]
    {:key prop
     :name (str engine " report paths")
     :default ""
     :doc (str "Paths to " engine " JSON reports. Findings arrive as external "
               "issues backed by ad-hoc rules, so configure the rules in "
               engine "'s own config rather than in a quality profile.")}))

(defn- property [{:keys [key name default doc]}]
  (-> (PropertyDefinition/builder key)
      (.name name)
      (.description doc)
      (.defaultValue default)
      (.category "Clojure")
      (.onConfigScopes (java.util.List/of PropertyDefinition$ConfigScope/PROJECT))
      (.multiValues true)
      (.build)))

(def ^:private extension-classes
  ["net.typemark.sonar.ClojureLanguage"
   "net.typemark.sonar.ClojureRulesDefinition"
   "net.typemark.sonar.ClojureQualityProfile"
   "net.typemark.sonar.KondoSensor"
   "net.typemark.sonar.ClojureSourceSensor"
   "net.typemark.sonar.CloverageSensor"
   "net.typemark.sonar.KaochaSensor"
   "net.typemark.sonar.ExternalAnalyzerSensor"
   "net.typemark.sonar.ExternalRulesDefinition"
   "net.typemark.sonar.ClojureMetrics"
   "net.typemark.sonar.CompletenessSensor"])

(defn- load-extension
  "Resolved by name because these are AOT artefacts of sibling namespaces.
  A missing class means a broken build, so it throws rather than degrading
  into a plugin that loads and does nothing."
  [^String n]
  (try
    (Class/forName n)
    (catch ClassNotFoundException e
      (throw (ex-info (str "sonar-clojure: extension class missing from the plugin jar: " n
                           " -- AOT compilation did not run or :ns-compile is incomplete")
                      {:class n} e)))))

(defn -define [_ ctx]
  ;; Printed once at load, so an operator reading sonar.log can see which
  ;; catalogues the running plugin was built from without unpacking the jar.
  (println "sonar-clojure:" (provenance/summary))
  (.addExtensions ctx (concat (map load-extension extension-classes)
                              (map property (concat property-specs external-property-specs))))
  nil)
