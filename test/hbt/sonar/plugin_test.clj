(ns hbt.sonar.plugin-test
  "Drives the AOT'd extension classes against the real plugin API. This is
  what tells you the plugin registers, not that it compiles."
  (:require [clojure.test :refer [deftest is testing]]
            [hbt.sonar.const :as const]
            [hbt.sonar.rules :as rules]
            [hbt.sonar.concurrency :as concurrency]
            [hbt.sonar.interop :as interop]
            [hbt.sonar.metadata :as metadata]
            [hbt.sonar.security :as security])
  (:import [org.sonar.api.rules RuleType]
           [org.sonar.api Plugin$Context SonarEdition SonarProduct SonarQubeSide SonarRuntime]
           [org.sonar.api.config Configuration]
           [org.sonar.api.server.rule RulesDefinition$Context]
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
  (let [lang (instantiate "hbt.sonar.ClojureLanguage" (config {}))]
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
      (let [l (instantiate "hbt.sonar.ClojureLanguage"
                           (config {const/suffixes-prop ".clj,.cljc"}))]
        (is (= [".clj" ".cljc"] (vec (.getFileSuffixes l))))
        (is (= ["**/*.clj" "**/*.cljc"] (vec (.filenamePatterns l))))))))

(deftest rules-definition-registers-every-kondo-linter
  (let [ctx  (RulesDefinition$Context.)
        _    (.define (instantiate "hbt.sonar.ClojureRulesDefinition") ctx)
        repo (.repository ctx const/repository-key)
        keys' (set (map #(.key %) (.rules repo)))]
    (is (some? repo) "repository was created")
    (testing "one rule per clj-kondo linter, the catch-all, and the security rules"
      (is (= (+ (count (rules/catalogue)) 1
                (count (distinct (concat security/rule-keys interop/rule-keys
                                         concurrency/rule-keys))))
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
        _    (.define (instantiate "hbt.sonar.ClojureRulesDefinition") ctx)
        repo (.repository ctx const/repository-key)
        by-key (into {} (map (juxt #(.key %) identity)) (.rules repo))]
    (testing "every rule the detection can raise is registered"
      (is (every? #(contains? by-key %)
                  (concat security/rule-keys interop/rule-keys concurrency/rule-keys))))
    (testing "every one ships a metadata resource pair -- a rule with no
              resource would be an issue Sonar drops on the floor"
      (is (every? #(some? (metadata/load-rule %))
                  (concat security/rule-keys interop/rule-keys concurrency/rule-keys))))
    (testing "and the loader refuses a key that ships none"
      (is (thrown? clojure.lang.ExceptionInfo (metadata/load-rules ["no-such-rule"]))))
    (testing "each carries its CWE, so the finding means something to a reviewer"
      (doseq [k (concat security/rule-keys interop/rule-keys)
              :let [rule (get by-key k)]
              :when (seq (:cwe (metadata/load-rule k)))]
        (is (some #(re-find #"cwe:" %) (.securityStandards rule))
            (str k " has no CWE"))))
    (testing "injection rules are vulnerabilities; review-me rules are hotspots"
      (is (= RuleType/VULNERABILITY (.type (get by-key "sql-string-built"))))
      (is (= RuleType/SECURITY_HOTSPOT (.type (get by-key "shell-invocation")))))
    (testing "OWASP category is attached, which is what the reports group by"
      (is (some #(re-find #"owaspTop10" %)
                (.securityStandards (get by-key "sql-string-built")))))))

(deftest plugin-registers-all-extensions
  (let [ctx (Plugin$Context. (runtime))]
    (.define (instantiate "hbt.sonar.ClojurePlugin") ctx)
    (let [exts    (.getExtensions ctx)
          classes (set (filter class? exts))
          props   (remove class? exts)]
      (testing "every extension class the plugin declares is registered"
        (is (= #{"hbt.sonar.ClojureLanguage"
                 "hbt.sonar.ClojureRulesDefinition"
                 "hbt.sonar.ClojureQualityProfile"
                 "hbt.sonar.KondoSensor"
                 "hbt.sonar.ClojureSourceSensor"
                 "hbt.sonar.CloverageSensor"
                 "hbt.sonar.KaochaSensor"
                 "hbt.sonar.ExternalAnalyzerSensor"
                 "hbt.sonar.ExternalRulesDefinition"}
               (set (map #(.getName ^Class %) classes)))))
      (testing "one property per report the plugin reads, plus file suffixes"
        (is (= 10 (count props)) "suffixes, patterns, 4 reports, 4 external analyzers")))))
