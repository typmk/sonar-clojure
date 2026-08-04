(ns hbt.sonar.completeness-test
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [hbt.sonar.completeness :as completeness]
            [hbt.sonar.metadata :as metadata]
            [hbt.sonar.report :as report]))

(deftest a-full-run-is-a-hundred-percent
  (let [r (completeness/assess (constantly true))]
    (is (= 100.0 (:percent r)))
    (is (empty? (:missing r)))))

(deftest nothing-measured-is-zero-not-clean
  (testing "the whole point: no inputs must not read as a clean project"
    (let [r (completeness/assess (constantly false))]
      (is (= 0.0 (:percent r)))
      (is (= (count report/inputs) (count (:missing r)))))))

(deftest the-percentage-tracks-what-is-present
  (let [r (completeness/assess #(= :kondo (:id %)))]
    (is (= 1 (:present r)))
    (is (= 25.0 (:percent r)))))

(deftest the-message-names-the-cost-not-only-the-file
  (let [m (completeness/message (completeness/assess #(not= :coverage (:id %))))]
    (is (str/includes? m "cloverage coverage"))
    (is (str/includes? m "quality gate")
        "a reviewer needs to know what the absence does, not just that it happened")
    (is (not (str/includes? m "clj-kondo findings"))
        "only the missing ones are named")))

(deftest the-registry-is-usable-by-everything-that-reads-it
  (testing "one table serves the property definitions, the sensors and this
            check; a missing field silently breaks whichever consumer needs it"
    (is (seq report/inputs))
    (doseq [{:keys [id prop default name doc label costs]} report/inputs]
      (is (keyword? id))
      (is (every? (comp seq str) [prop default name doc label costs])
          (str id " is missing a field some consumer of the registry needs")))
    (is (= (count report/inputs) (count (distinct (map :id report/inputs))))))
  (testing "an unknown id throws rather than resolving to no paths at all"
    (is (thrown? clojure.lang.ExceptionInfo (report/input :nope)))))

(deftest the-rule-it-raises-is-registered
  (is (contains? (set (metadata/all-keys)) "incomplete-analysis")
      "an issue against an unregistered rule is dropped without a message"))

(deftest rule-metadata-is-not-shadowed-by-a-stale-build
  (testing "target/classes precedes resources on the classpath; a resource copy
            there means the suite validates the last build, not the source"
    (is (not (.exists (io/file "target/classes/org/sonar/l10n")))
        "build.clj must stage resources into target/stage, never target/classes")))
