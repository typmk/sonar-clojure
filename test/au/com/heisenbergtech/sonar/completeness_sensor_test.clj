(ns au.com.heisenbergtech.sonar.completeness-sensor-test
  "The sensor run against SonarSource's own in-memory SensorContext.

  The helpers in `au.com.heisenbergtech.sonar.completeness` are pure and were already covered.
  What that cannot show is whether the measure and the issue survive the Sonar
  API calls -- the metric has to be one the context accepts, the issue has to
  name a registered rule, and the project has to be a valid InputComponent.
  Every one of those fails at runtime, in the scanner, silently."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [au.com.heisenbergtech.sonar.report :as report]
            [au.com.heisenbergtech.sonar.metrics-def :as metrics-def])
  (:import [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]
           [org.sonar.api.batch.sensor.internal SensorContextTester]
           [au.com.heisenbergtech.sonar CompletenessSensor]))

(defn- temp-dir ^java.io.File []
  (.toFile (Files/createTempDirectory "completeness" (into-array FileAttribute []))))

(defn- run
  "Runs the sensor over a base dir holding `files`, with `props` set.
  Returns {:measure v :issues [...]}"
  [files props]
  (let [base (temp-dir)]
    (doseq [f files]
      (let [t (io/file base f)]
        (io/make-parents t)
        (spit t "{}")))
    (let [ctx (SensorContextTester/create base)]
      (doseq [[k v] props] (.setProperty (.settings ctx) ^String k ^String v))
      (.execute (CompletenessSensor.) ctx)
      {:measure (some-> (.measure ctx (.key (.project ctx)) metrics-def/completeness-key)
                        (.value))
       :issues  (vec (.allIssues ctx))})))

(def ^:private all-four
  ["target/clj-kondo.json" "target/clj-kondo-analysis.json"
   "target/coverage/codecov.json" "target/junit.xml"])

(deftest a-complete-run-reports-a-hundred-and-raises-nothing
  (let [{:keys [measure issues]} (run all-four {})]
    (is (= 100.0 measure))
    (is (empty? issues) "a fully measured project must not carry this issue")))

(deftest no-reports-at-all-reports-zero-and-raises-the-issue
  (testing "the failure the whole namespace exists for: nothing measured must
            not present as a clean project"
    (let [{:keys [measure issues]} (run [] {})]
      (is (= 0.0 measure))
      (is (= 1 (count issues)))
      (let [i (first issues)]
        (is (= "clj-kondo" (.repository (.ruleKey i))))
        (is (= "incomplete-analysis" (.rule (.ruleKey i))))
        (is (instance? org.sonar.api.scanner.fs.InputProject
                       (.inputComponent (.primaryLocation i)))
            "the issue lands on the project, not on a file")))))

(deftest the-issue-names-every-missing-input-and-its-cost
  (let [{:keys [issues]} (run ["target/clj-kondo.json"] {})
        msg (.message (.primaryLocation (first issues)))]
    (is (str/includes? msg "1 of 4"))
    (is (str/includes? msg "cloverage coverage"))
    (is (str/includes? msg "kaocha test execution"))
    (is (not (str/includes? msg "clj-kondo findings"))
        "the input that was present must not be listed as missing")))

(deftest a-configured-path-counts-as-well-as-the-default
  (testing "a project that writes elsewhere is complete, not incomplete"
    (let [{:keys [measure]} (run ["build/kondo.json" "target/clj-kondo-analysis.json"
                                  "target/coverage/codecov.json" "target/junit.xml"]
                                 {(:prop (report/input :kondo)) "build/kondo.json"})]
      (is (= 100.0 measure)))))

(deftest a-configured-path-that-does-not-exist-is-missing
  (testing "pointing at a file that was never written is exactly the case the
            metric must catch -- the property being set proves nothing"
    (let [{:keys [measure issues]} (run all-four {(:prop (report/input :kondo)) "build/kondo.json"})]
      (is (= 75.0 measure)
          "the configured path overrides the default; the default file is irrelevant")
      (is (= 1 (count issues))))))
