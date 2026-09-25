(ns net.typemark.sonar.plugin
  "Entry point named by Plugin-Class in the jar manifest."
  (:require [clojure.string :as str]
            [net.typemark.sonar.const :as const]
            [net.typemark.sonar.completeness-sensor :as completeness-sensor]
            [net.typemark.sonar.coverage-sensor :as coverage-sensor]
            [net.typemark.sonar.external-rules :as external-rules]
            [net.typemark.sonar.external-sensor :as external-sensor]
            [net.typemark.sonar.inputs :as inputs]
            [net.typemark.sonar.kondo-sensor :as kondo-sensor]
            [net.typemark.sonar.language]
            [net.typemark.sonar.metrics-def :as metrics-def]
            [net.typemark.sonar.profile :as profile]
            [net.typemark.sonar.provenance :as provenance]
            [net.typemark.sonar.rules :as rules]
            [net.typemark.sonar.source-sensor :as source-sensor]
            [net.typemark.sonar.test-sensor :as test-sensor])
  (:import [org.sonar.api.batch.sensor Sensor SensorDescriptor]
           [org.sonar.api.config PropertyDefinition PropertyDefinition$ConfigScope]
           [org.sonar.api.measures Metrics]
           [org.sonar.api.server.profile BuiltInQualityProfilesDefinition]
           [org.sonar.api.server.rule RulesDefinition])
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

(defn- sensor
  "A Sensor from a name and a function of the SensorContext. Sonar takes an
  extension as a class to instantiate or as an object; an object needs no
  gen-class, no AOT-named class and no lookup by name."
  [^String sensor-name execute!]
  (reify
    Object
    (toString [_] (str "sonar-clojure sensor: " sensor-name))
    Sensor
    (describe [_ d]
      (let [^SensorDescriptor d d]
        (-> d (.name sensor-name) (.onlyOnLanguage const/language-key))))
    (execute [_ ctx]
      (execute! ctx))))

(def sensors
  "Every sensor, in the order Sonar logs them."
  [["clj-kondo"                            kondo-sensor/execute!]
   ["Clojure source measures and security" source-sensor/execute!]
   ["cloverage"                            coverage-sensor/execute!]
   ["kaocha test execution"                test-sensor/execute!]
   ["Clojure external analyzers"           external-sensor/execute!]
   ["Clojure analysis completeness"        completeness-sensor/execute!]])

(defn extensions
  "What the plugin registers. The language stays a class: its constructor
  takes the project's Configuration, which is where per-project suffixes
  live, and an instance made here would see only the boot configuration."
  []
  (concat
   [(Class/forName "net.typemark.sonar.ClojureLanguage")
    (reify RulesDefinition (define [_ ctx] (rules/define! ctx)))
    (reify RulesDefinition (define [_ ctx] (external-rules/define! ctx)))
    (reify BuiltInQualityProfilesDefinition (define [_ ctx] (profile/define! ctx)))
    (reify Metrics (getMetrics [_] [metrics-def/completeness]))]
   (for [[n f] sensors] (sensor n f))
   (map property (concat property-specs external-property-specs))))

(defn -define [_ ctx]
  ;; Printed once at load, so an operator reading sonar.log can see which
  ;; catalogues the running plugin was built from without unpacking the jar.
  (println "sonar-clojure:" (provenance/summary))
  (.addExtensions ctx (vec (extensions)))
  nil)
