(ns net.typemark.sonar.plugin-test
  "Drives the plugin's extensions against the real plugin API. This is what
  tells you the plugin registers, not that it compiles."
  (:require [clojure.test :refer [deftest is testing]]
            [net.typemark.sonar.const :as const]
            [net.typemark.sonar.plugin :as plugin]
            [net.typemark.sonar.rules :as rules]
            [net.typemark.sonar.metadata :as metadata])
  (:import [org.sonar.api.rules RuleType]
           [org.sonar.api Plugin$Context SonarEdition SonarProduct SonarQubeSide SonarRuntime]
           [org.sonar.api.batch.sensor Sensor]
           [org.sonar.api.batch.sensor.internal DefaultSensorDescriptor]
           [org.sonar.api.config Configuration PropertyDefinition]
           [org.sonar.api.measures Metrics]
           [org.sonar.api.server.profile BuiltInQualityProfilesDefinition]
           [org.sonar.api.server.rule RulesDefinition RulesDefinition$Context]
           [org.sonar.api.utils Version]))

(defn- config ^Configuration [m]
  (reify Configuration
    (get [_ k] (java.util.Optional/ofNullable (get m k)))
    (hasKey [_ k] (contains? m k))
    (getStringArray [_ k]
      (into-array String (if-let [v (get m k)] (.split ^String v ",") [])))))

(defn- runtime ^SonarRuntime []
  (reify SonarRuntime
    (getApiVersion [_] (Version/parse "13.9"))
    (getProduct [_] SonarProduct/SONARQUBE)
    (getSonarQubeSide [_] SonarQubeSide/SCANNER)
    (getEdition [_] SonarEdition/COMMUNITY)))

(defn- instantiate [^String cls & args]
  (let [c (Class/forName cls)]
    (if (seq args)
      (.newInstance (first (.getConstructors c)) (into-array Object args))
      (.newInstance (.getDeclaredConstructor c (into-array Class [])) (into-array Object [])))))

(deftest language-claims-clojure-extensions
  (let [lang (instantiate "net.typemark.sonar.ClojureLanguage" (config {}))]
    (is (= "clj" (.getKey lang)))
    (is (= "Clojure" (.getName lang)))
    (testing "defaults cover the four dialects plus edn and bb"
      (is (= [".clj" ".cljs" ".cljc" ".edn" ".bb"] (vec (.getFileSuffixes lang)))))
    (testing "filename patterns are DERIVED, never stubbed empty -- an empty
              array makes the scanner claim nothing and skip every sensor,
              silently"
      (is (= ["**/*.clj" "**/*.cljs" "**/*.cljc" "**/*.edn" "**/*.bb"]
             (vec (.filenamePatterns lang)))))
    (testing "and are overridable, which is why the ctor takes Configuration"
      (let [l (instantiate "net.typemark.sonar.ClojureLanguage"
                           (config {const/suffixes-prop ".clj,.cljc"}))]
        (is (= [".clj" ".cljc"] (vec (.getFileSuffixes l))))
        (is (= ["**/*.clj" "**/*.cljc"] (vec (.filenamePatterns l))))))))

(deftest rules-definition-registers-every-kondo-linter
  (let [ctx  (RulesDefinition$Context.)
        _    (rules/define! ctx)
        repo (.repository ctx const/repository-key)
        keys' (set (map #(.key %) (.rules repo)))]
    (is (some? repo) "repository was created")
    (testing "one rule per clj-kondo linter, the catch-all, and the security rules"
      (is (= (+ (count (rules/catalogue)) 1 (count (metadata/all-keys)))
             (count (.rules repo)))))
    (testing "the catch-all exists, so a newer clj-kondo cannot drop findings"
      (is (contains? keys' const/unknown-rule)))
    (testing "known linters are present under their own key"
      (is (contains? keys' "unresolved-symbol"))
      (is (contains? keys' "type-mismatch")))
    (let [hotspot?  #(= RuleType/SECURITY_HOTSPOT (.type %))
          hotspots  (filter hotspot? (.rules repo))
          ordinary  (remove hotspot? (.rules repo))]
      (testing "a hotspot is outside the clean-code model -- Sonar carries no
                attribute or impact for something not yet known to be a defect"
        (is (seq hotspots))
        (is (every? #(nil? (.cleanCodeAttribute %)) hotspots))
        (is (every? #(empty? (.defaultImpacts %)) hotspots)))
      (testing "every other rule carries both"
        (is (every? #(some? (.cleanCodeAttribute %)) ordinary))
        (is (every? #(seq (.defaultImpacts %)) ordinary))))))

(deftest security-rules-carry-the-standards-that-drive-security-reports
  (let [ctx  (RulesDefinition$Context.)
        _    (rules/define! ctx)
        repo (.repository ctx const/repository-key)
        by-key (into {} (map (juxt #(.key %) identity)) (.rules repo))]
    (testing "every rule the detection can raise is registered"
      (is (every? #(contains? by-key %)
                  (metadata/all-keys))))
    (testing "every one ships a metadata resource pair -- a rule with no
              resource would be an issue Sonar drops on the floor"
      (is (every? #(some? (metadata/load-rule %))
                  (metadata/all-keys))))
    (testing "and the loader refuses a key that ships none"
      (is (thrown? clojure.lang.ExceptionInfo (metadata/load-rules ["no-such-rule"]))))
    (testing "each carries its CWE, so the finding means something to a reviewer"
      (doseq [k (metadata/all-keys)
              :let [rule (get by-key k)]
              :when (seq (:cwe (metadata/load-rule k)))]
        (is (some #(re-find #"cwe:" %) (.securityStandards rule))
            (str k " has no CWE"))))
    (testing "injection rules are vulnerabilities; review-me rules are hotspots.
              The metadata migration flattened four of these to VULNERABILITY
              because the dedupe took the wrong duplicate first."
      (is (= RuleType/VULNERABILITY (.type (get by-key "sql-string-built"))))
      (doseq [k ["shell-invocation" "reflective-call" "permissive-file-permissions"
                 "xml-external-entity"]]
        (is (= RuleType/SECURITY_HOTSPOT (.type (get by-key k))) k)))
    (testing "OWASP category is attached, which is what the reports group by"
      (is (some #(re-find #"owaspTop10" %)
                (.securityStandards (get by-key "sql-string-built")))))))

(defn- described [^Sensor s]
  (let [d (DefaultSensorDescriptor.)]
    (.describe s d)
    {:name (.name d) :languages (vec (.languages d))}))

(deftest plugin-registers-all-extensions
  (let [ctx (Plugin$Context. (runtime))]
    (.define (instantiate "net.typemark.sonar.ClojurePlugin") ctx)
    (let [exts    (vec (.getExtensions ctx))
          of      (fn [^Class c] (filter #(instance? c %) exts))]
      (testing "the language is the one class, because it takes the project's Configuration"
        (is (= ["net.typemark.sonar.ClojureLanguage"]
               (map #(.getName ^Class %) (filter class? exts)))))
      (testing "every sensor is an instance, named and scoped to Clojure"
        (is (= (map (fn [[n]] {:name n :languages [const/language-key]}) plugin/sensors)
               (map described (of Sensor)))))
      (testing "two rule repositories, one profile, one metric"
        (is (= 2 (count (of RulesDefinition))))
        (is (= 1 (count (of BuiltInQualityProfilesDefinition))))
        (is (= ["clj_analysis_completeness"]
               (map #(.getKey %) (mapcat #(.getMetrics ^Metrics %) (of Metrics))))))
      (testing "every extension is either the language class or an instance Sonar can use"
        (is (= (count exts)
               (+ 1 (count (of Sensor)) (count (of RulesDefinition))
                  (count (of BuiltInQualityProfilesDefinition)) (count (of Metrics))
                  (count (of PropertyDefinition))))))
      (testing "one property per report the plugin reads, plus file suffixes"
        (is (= 11 (count (of PropertyDefinition)))
            "suffixes, patterns, 4 reports, 5 external analyzers")))))

(deftest the-rule-repositories-are-reachable-through-the-plugin
  (let [ctx (RulesDefinition$Context.)]
    (doseq [^RulesDefinition d (filter #(instance? RulesDefinition %) (plugin/extensions))]
      (.define d ctx))
    (is (some? (.repository ctx const/repository-key)))
    (is (< 1 (count (.repositories ctx))) "the external analyzers' too")))
