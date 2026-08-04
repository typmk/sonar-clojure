(ns hbt.sonar.plugin
  "Entry point named by Plugin-Class in the jar manifest."
  (:require [clojure.string :as str]
            [hbt.sonar.const :as const]
            ;; required so their AOT'd classes are loadable by name below
            [hbt.sonar.coverage-sensor]
            [hbt.sonar.language]
            [hbt.sonar.profile]
            [hbt.sonar.rules]
            [hbt.sonar.sensor]
            [hbt.sonar.source-sensor]
            [hbt.sonar.test-sensor]
            [hbt.sonar.external-sensor]
            [hbt.sonar.external-rules])
  (:import [org.sonar.api.config PropertyDefinition PropertyDefinition$ConfigScope])
  (:gen-class
   :name hbt.sonar.ClojurePlugin
   :implements [org.sonar.api.Plugin]))

(def ^:private property-specs
  "Four properties differing only in key, name, default and prose -- so they
  are a table, not four builder blocks."
  [{:key     const/suffixes-prop
    :name    "File suffixes"
    :default (str/join "," const/default-suffixes)
    :doc     "Comma-separated file suffixes analysed as Clojure."}

   {:key     const/patterns-prop
    :name    "File patterns"
    :default (str/join "," (map #(str "**/*" %) const/default-suffixes))
    :doc     "Glob patterns analysed as Clojure. Read by the scanner's language detection."}

   {:key     const/report-paths-prop
    :name    "clj-kondo report paths"
    :default const/default-report
    :doc     (str "Paths to clj-kondo JSON reports, relative to the module base. "
                  "Produce one with: clj-kondo --lint src test "
                  "--config '{:output {:format :json}}' > target/clj-kondo.json")}

   {:key     const/analysis-paths-prop
    :name    "clj-kondo analysis paths"
    :default const/default-analysis
    :doc     (str "Paths to clj-kondo analysis JSON, which drives symbol navigation. "
                  "Produce one with: clj-kondo --lint src test --config "
                  "'{:output {:format :json :analysis {:locals true}}}' "
                  "> target/clj-kondo-analysis.json")}

   {:key     const/test-report-paths-prop
    :name    "kaocha JUnit report paths"
    :default const/default-test-report
    :doc     (str "Paths to kaocha's JUnit XML. Produce one by adding the "
                  "kaocha-junit-xml plugin and running: "
                  "bin/kaocha --plugin kaocha.plugin/junit-xml "
                  "--junit-xml-file target/junit.xml")}

   {:key     const/coverage-paths-prop
    :name    "cloverage lcov paths"
    :default const/default-coverage
    :doc     (str "Paths to cloverage lcov reports. Produce one with: "
                  "clojure -M:test -m cloverage.coverage --lcov -p src -s test")}])

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
  ["hbt.sonar.ClojureLanguage"
   "hbt.sonar.ClojureRulesDefinition"
   "hbt.sonar.ClojureQualityProfile"
   "hbt.sonar.KondoSensor"
   "hbt.sonar.ClojureSourceSensor"
   "hbt.sonar.CloverageSensor"
   "hbt.sonar.KaochaSensor"
   "hbt.sonar.ExternalAnalyzerSensor"
   "hbt.sonar.ExternalRulesDefinition"])

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
  (.addExtensions ctx (concat (map load-extension extension-classes)
                              (map property (concat property-specs external-property-specs))))
  nil)
