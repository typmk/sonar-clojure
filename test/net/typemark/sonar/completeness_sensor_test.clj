(ns net.typemark.sonar.completeness-sensor-test
  "The sensor run against SonarSource's own in-memory SensorContext.

  The helpers in `net.typemark.sonar.completeness` are pure and were already covered.
  What that cannot show is whether the measure and the issue survive the Sonar
  API calls -- the metric has to be one the context accepts, the issue has to
  name a registered rule, and the project has to be a valid InputComponent.
  Every one of those fails at runtime, in the scanner, silently."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [net.typemark.sonar.inputs :as inputs]
            [net.typemark.sonar.metrics-def :as metrics-def])
  (:import [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]
           [org.sonar.api.batch.sensor.internal SensorContextTester]
           [net.typemark.sonar CompletenessSensor]))

(defn- temp-dir ^java.io.File []
  (.toFile (Files/createTempDirectory "completeness" (into-array FileAttribute []))))

(def ^:private kondo-json
  "What one clj-kondo run with :analysis writes: both halves in one document."
  "{\"findings\":[],\"analysis\":{}}")

(defn- run
  "Runs the sensor over a base dir holding `files`, with `props` set. `files`
  is paths, each written as a report carrying findings and analysis, or
  [path content] pairs.
  Returns {:measure v :issues [...]}"
  [files props]
  (let [base (temp-dir)]
    (doseq [f files]
      (let [[f content] (if (string? f) [f kondo-json] f)
            t (io/file base f)]
        (io/make-parents t)
        (spit t content)))
    (let [ctx (SensorContextTester/create base)]
      (doseq [[k v] props] (.setProperty (.settings ctx) ^String k ^String v))
      (.execute (CompletenessSensor.) ctx)
      {:measure (some-> (.measure ctx (.key (.project ctx)) metrics-def/completeness-key)
                        (.value))
       :issues  (vec (.allIssues ctx))})))

(def ^:private all-four
  "Four inputs, three files: one clj-kondo run is the findings and the analysis."
  ["target/clj-kondo.json" "target/coverage/codecov.json" "target/junit.xml"])

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
    (is (str/includes? msg "2 of 4")
        "one clj-kondo report is two inputs: its findings and its analysis")
    (is (str/includes? msg "cloverage coverage"))
    (is (str/includes? msg "kaocha test execution"))
    (is (not (str/includes? msg "clj-kondo findings"))
        "the input that was present must not be listed as missing")))

(deftest a-configured-path-counts-as-well-as-the-default
  (testing "a project that writes elsewhere is complete, not incomplete"
    (let [{:keys [measure]} (run ["build/kondo.json" "target/clj-kondo-analysis.json"
                                  "target/coverage/codecov.json" "target/junit.xml"]
                                 {(:prop (inputs/input :kondo)) "build/kondo.json"
                                  (:prop (inputs/input :analysis)) "target/clj-kondo-analysis.json"})]
      (is (= 100.0 measure)))))

(deftest a-findings-only-report-is-missing-its-analysis
  (testing "the analysis defaults to the findings report, so a report written
            without :analysis must read as analysis missing, not as complete"
    (let [{:keys [measure issues]} (run [["target/clj-kondo.json" "{\"findings\":[]}"]
                                         "target/coverage/codecov.json" "target/junit.xml"]
                                        {})
          msg (.message (.primaryLocation (first issues)))]
      (is (= 75.0 measure))
      (is (str/includes? msg "clj-kondo analysis"))
      (is (not (str/includes? msg "clj-kondo findings"))))))

(deftest a-configured-path-that-does-not-exist-is-missing
  (testing "pointing at a file that was never written is exactly the case the
            metric must catch -- the property being set proves nothing"
    (let [{:keys [measure issues]} (run all-four {(:prop (inputs/input :kondo)) "build/kondo.json"})]
      (is (= 75.0 measure)
          "the configured path overrides the default; the default file is irrelevant")
      (is (= 1 (count issues))))))
