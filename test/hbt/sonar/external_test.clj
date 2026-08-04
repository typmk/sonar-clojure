(ns hbt.sonar.external-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [hbt.sonar.external :as external]))

(def report
  (str "{\"findings\":["
       "{\"filename\":\"src/a.clj\",\"row\":3,\"col\":5,\"end-row\":3,\"end-col\":9,"
       "\"level\":\"warning\",\"type\":\"prefer-condp\",\"message\":\"use condp\"},"
       "{\"filename\":\"src/b.clj\",\"row\":1,\"col\":1,"
       "\"level\":\"error\",\"type\":\"sql-injection\",\"message\":\"unsafe\"}"
       "],\"summary\":{}}"))

(deftest reads-the-kondo-shape-splint-and-clj-holmes-both-emit
  (let [fs (external/findings "splint" report)]
    (is (= 2 (count fs)))
    (is (= {:engine "splint" :rule "prefer-condp" :filename "src/a.clj"
            :line 3 :col 5 :end-line 3 :end-col 9
            :severity "MEDIUM" :message "use condp"}
           (first fs)))
    (testing "a missing end position falls back to the start"
      (is (= 1 (:end-line (second fs)))))
    (testing "level maps to impact severity"
      (is (= "HIGH" (:severity (second fs)))))))

(deftest each-distinct-rule-needs-an-ad-hoc-declaration
  (is (= #{["splint" "prefer-condp"] ["splint" "sql-injection"]}
         (external/rule-ids (external/findings "splint" report)))))

(deftest an-unrecognised-shape-yields-nil-not-zero-findings
  (testing "nil is distinguishable from 'ran and found nothing'; 0 is not"
    (is (nil? (external/findings "splint" "{\"something\":\"else\"}")))
    (is (nil? (external/findings "splint" "not json at all")))
    (is (nil? (external/findings "splint" "")))))

(deftest every-engine-declares-how-its-findings-are-classified
  (doseq [[id {:keys [name quality type]}] external/engines]
    (is (string? name) id)
    (is (contains? #{"MAINTAINABILITY" "RELIABILITY" "SECURITY"} quality) id)
    (is (contains? #{"CODE_SMELL" "BUG" "VULNERABILITY"} type) id)))

(defspec never-throws-and-always-yields-usable-positions 300
  (prop/for-all [s gen/string]
    (let [fs (external/findings "splint" s)]
      (or (nil? fs)
          (every? #(and (>= (:line %) 1) (>= (:col %) 1)) fs)))))
