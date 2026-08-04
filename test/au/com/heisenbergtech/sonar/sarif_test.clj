(ns au.com.heisenbergtech.sonar.sarif-test
  "SARIF import, so opengrep's taint findings reach the dashboard.

  Severity is the trap: SARIF puts it on the RULE as
  defaultConfiguration.level, not on the result. Reading it off the result
  yields nil for every finding and flattens the whole report to one severity,
  which is exactly the kind of silent degradation that looks like it worked."
  (:require [clojure.test :refer [deftest is testing]]
            [au.com.heisenbergtech.sonar.external :as external]))

(def ^:private sarif
  (str "{\"runs\":[{\"tool\":{\"driver\":{\"name\":\"Opengrep OSS\",\"rules\":["
       "{\"id\":\"clj-sql-injection\",\"defaultConfiguration\":{\"level\":\"error\"}},"
       "{\"id\":\"clj-ssrf\",\"defaultConfiguration\":{\"level\":\"warning\"}}]}},"
       "\"results\":["
       "{\"ruleId\":\"clj-sql-injection\",\"message\":{\"text\":\"input reaches SQL\"},"
       "\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"src/a.clj\"},"
       "\"region\":{\"startLine\":7,\"startColumn\":21,\"endLine\":7,\"endColumn\":43}}}]},"
       "{\"ruleId\":\"clj-ssrf\",\"message\":{\"text\":\"input reaches http\"},"
       "\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"src/b.clj\"},"
       "\"region\":{\"startLine\":3,\"startColumn\":1,\"endLine\":3,\"endColumn\":9}}}]}]}]}"))

(deftest reads-sarif
  (let [fs (external/findings "opengrep" sarif)]
    (is (= 2 (count fs)))
    (let [f (first fs)]
      (is (= "clj-sql-injection" (:rule f)))
      (is (= "src/a.clj" (:filename f)))
      (is (= [7 21 7 43] [(:line f) (:col f) (:end-line f) (:end-col f)]))
      (is (= "input reaches SQL" (:message f)))
      (is (= "opengrep" (:engine f))))))

(deftest severity-comes-from-the-rule-not-the-result
  (testing "SARIF carries level on the rule; reading the result gives nil for
            every finding and collapses the report to one severity"
    (let [by-rule (into {} (map (juxt :rule :severity)) (external/findings "opengrep" sarif))]
      (is (= "HIGH" (get by-rule "clj-sql-injection")))
      (is (= "MEDIUM" (get by-rule "clj-ssrf")))
      (is (not= (get by-rule "clj-sql-injection") (get by-rule "clj-ssrf"))
          "two different rule levels must not flatten to one"))))

(deftest the-kondo-shape-still-reads
  (testing "adding SARIF must not break splint, clj-holmes or eastwood"
    (let [fs (external/findings "splint"
               (str "{\"findings\":[{\"filename\":\"src/c.clj\",\"row\":2,\"col\":3,"
                    "\"level\":\"warning\",\"type\":\"style/x\",\"message\":\"m\"}]}"))]
      (is (= 1 (count fs)))
      (is (= "style/x" (:rule (first fs))))
      (is (= "MEDIUM" (:severity (first fs)))))))

(deftest neither-shape-throws-on-junk
  (doseq [t ["" "{}" "null" "not json" "{\"runs\":[]}" "{\"runs\":{}}"
             "{\"runs\":[{\"results\":[{}]}]}"]]
    (is (nil? (try (doall (external/findings "opengrep" t)) nil (catch Throwable e e)))
        (str "threw on " (pr-str t)))))

(deftest a-rule-id-does-not-carry-the-machine-it-was-scanned-on
  (testing "opengrep derives the SARIF rule id from the path its config was
            loaded from, so an absolute -f yields a key containing the
            developer's home directory -- the same finding then arrives under
            different keys locally and in CI, and Sonar tracks two issues"
    (let [long-id (str "{\"runs\":[{\"tool\":{\"driver\":{\"rules\":[]}},\"results\":["
                       "{\"ruleId\":\"home.apollon.GitHub.proj.opengrep.clj-sql-injection\","
                       "\"message\":{\"text\":\"m\"},\"locations\":[{\"physicalLocation\":"
                       "{\"artifactLocation\":{\"uri\":\"src/a.clj\"},"
                       "\"region\":{\"startLine\":1,\"startColumn\":1}}}]}]}]}")]
      (is (= "clj-sql-injection" (:rule (first (external/findings "opengrep" long-id))))))))

(deftest opengrep-is-a-declared-engine
  (is (contains? external/engines "opengrep"))
  (is (= "VULNERABILITY" (get-in external/engines ["opengrep" :type]))))

(deftest a-security-engine-is-not-filed-as-a-code-smell
  (testing "the issue's type and quality come from the engine, not a constant.
            Hardcoding them filed every clj-holmes, nvd and opengrep finding as
            a maintainability code smell, and put the issue's severity on a
            different software quality than the rule's default -- so the
            dashboard showed MEDIUM for a finding derived as HIGH"
    (doseq [e ["clj-holmes" "nvd" "opengrep"]]
      (is (= "VULNERABILITY" (get-in external/engines [e :type])) e)
      (is (= "SECURITY" (get-in external/engines [e :quality])) e))
    (is (= "CODE_SMELL" (get-in external/engines ["splint" :type])))
    (is (= "BUG" (get-in external/engines ["eastwood" :type])))))
