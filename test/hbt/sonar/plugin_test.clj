(ns hbt.sonar.plugin-test
  "Drives the AOT'd extension classes against the real plugin API. This is
  what tells you the plugin registers, not that it compiles."
  (:require [clojure.test :refer [deftest is testing]]
            [hbt.sonar.const :as const]
            [hbt.sonar.rules :as rules])
  (:import [org.sonar.api Plugin$Context SonarEdition SonarProduct SonarQubeSide SonarRuntime]
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
    (testing "and are overridable, which is why the ctor takes Configuration"
      (let [l (instantiate "hbt.sonar.ClojureLanguage"
                           (config {const/suffixes-prop ".clj,.cljc"}))]
        (is (= [".clj" ".cljc"] (vec (.getFileSuffixes l))))))))

(deftest rules-definition-registers-every-kondo-linter
  (let [ctx  (RulesDefinition$Context.)
        _    (.define (instantiate "hbt.sonar.ClojureRulesDefinition") ctx)
        repo (.repository ctx const/repository-key)
        keys' (set (map #(.key %) (.rules repo)))]
    (is (some? repo) "repository was created")
    (testing "one rule per clj-kondo linter, plus the unknown-linter catch-all"
      (is (= (inc (count (rules/catalogue))) (count (.rules repo)))))
    (testing "the catch-all exists, so a newer clj-kondo cannot drop findings"
      (is (contains? keys' const/unknown-rule)))
    (testing "known linters are present under their own key"
      (is (contains? keys' "unresolved-symbol"))
      (is (contains? keys' "type-mismatch")))
    (testing "every rule carries a clean-code attribute and an impact"
      (is (every? #(some? (.cleanCodeAttribute %)) (.rules repo)))
      (is (every? #(seq (.defaultImpacts %)) (.rules repo))))))

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
                 "hbt.sonar.CloverageSensor"}
               (set (map #(.getName ^Class %) classes)))))
      (testing "one property per report the plugin reads, plus file suffixes"
        (is (= 4 (count props)))))))
