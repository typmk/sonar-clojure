(ns au.com.heisenbergtech.sonar.plugin
  "Entry point named by Plugin-Class in the jar manifest."
  (:require [clojure.string :as str]
            [au.com.heisenbergtech.sonar.const :as const]
            [au.com.heisenbergtech.sonar.coverage-sensor]
            [au.com.heisenbergtech.sonar.language]
            [au.com.heisenbergtech.sonar.profile]
            [au.com.heisenbergtech.sonar.report :as report]
            [au.com.heisenbergtech.sonar.provenance :as provenance]
            [au.com.heisenbergtech.sonar.rules]
            [au.com.heisenbergtech.sonar.sensor]
            [au.com.heisenbergtech.sonar.source-sensor]
            [au.com.heisenbergtech.sonar.test-sensor]
            [au.com.heisenbergtech.sonar.external-sensor]
            [au.com.heisenbergtech.sonar.external-rules])
  (:import [org.sonar.api.config PropertyDefinition PropertyDefinition$ConfigScope])
  (:gen-class
   :name au.com.heisenbergtech.sonar.ClojurePlugin
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
   (for [{:keys [prop name default doc]} report/inputs]
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
  ["au.com.heisenbergtech.sonar.ClojureLanguage"
   "au.com.heisenbergtech.sonar.ClojureRulesDefinition"
   "au.com.heisenbergtech.sonar.ClojureQualityProfile"
   "au.com.heisenbergtech.sonar.KondoSensor"
   "au.com.heisenbergtech.sonar.ClojureSourceSensor"
   "au.com.heisenbergtech.sonar.CloverageSensor"
   "au.com.heisenbergtech.sonar.KaochaSensor"
   "au.com.heisenbergtech.sonar.ExternalAnalyzerSensor"
   "au.com.heisenbergtech.sonar.ExternalRulesDefinition"
   "au.com.heisenbergtech.sonar.ClojureMetrics"
   "au.com.heisenbergtech.sonar.CompletenessSensor"])

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
