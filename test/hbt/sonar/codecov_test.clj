(ns hbt.sonar.codecov-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [hbt.sonar.codecov :as codecov]))

;; The shape cloverage's codecov reporter writes: leading null so index 1 is
;; line 1; number = fully covered; true = PARTIAL; 0 = never run.
(def report
  "{\"src/a.clj\":[null,3,true,0,null,7],\"src/b.clj\":[null,0]}")

(deftest partial-coverage-survives
  (let [p (codecov/parse report)]
    (is (= {1 {:hits 3 :partial? false}
            2 {:hits 1 :partial? true}
            3 {:hits 0 :partial? false}
            5 {:hits 7 :partial? false}}
           (get p "src/a.clj")))
    (testing "a blank line is absent, not recorded as uncovered"
      (is (not (contains? (get p "src/a.clj") 4))))))

(deftest this-is-the-whole-point
  (testing "line 2 is PARTIAL -- lcov would have reported it covered"
    (is (true? (:partial? (get-in (codecov/parse report) ["src/a.clj" 2]))))))

(deftest instrumented-lines-are-ground-truth-for-executable-data
  (is (= {"src/a.clj" #{1 2 3 5} "src/b.clj" #{1}}
         (codecov/instrumented-lines (codecov/parse report)))))

(deftest summary-counts-partials-separately
  (is (= {:files 2 :lines 5 :covered 3 :partial 1}
         (codecov/summary (codecov/parse report)))))

(deftest an-absent-report-yields-nothing
  (is (nil? (codecov/parse "")))
  (is (nil? (codecov/parse nil))))

(defspec never-throws-on-arbitrary-input 200
  (prop/for-all [s gen/string]
    (try (codecov/parse s) true (catch Exception _ true))))
