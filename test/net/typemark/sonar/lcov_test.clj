(ns net.typemark.sonar.lcov-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [net.typemark.sonar.lcov :as lcov]))

(def report
  (str "TN:\n"
       "SF:src/lume/res.clj\n"
       "DA:1,1\n"
       "DA:2,0\n"
       "DA:7,3\n"
       "end_of_record\n"
       "SF:src/lume/db.clj\n"
       "DA:1,0\n"
       "end_of_record\n"))

(deftest parses-lcov
  (let [p (lcov/parse report)]
    (is (= #{"src/lume/res.clj" "src/lume/db.clj"} (set (keys p))))
    (is (= {1 1, 2 0, 7 3} (get p "src/lume/res.clj")))
    (testing "an uncovered line is recorded as zero hits, not omitted"
      (is (= 0 (get-in p ["src/lume/db.clj" 1]))))))

(deftest summarises-what-the-report-claims
  (is (= {:files 2 :lines 4 :hit 2} (lcov/covered-summary (lcov/parse report)))))

(deftest repeated-records-take-the-higher-count
  (testing "two runs over the same file mean the line was reached"
    (is (= {1 5} (get (lcov/parse "SF:a.clj\nDA:1,0\nend_of_record\nSF:a.clj\nDA:1,5\nend_of_record\n")
                      "a.clj")))))

(deftest a-line-outside-a-file-section-is-ignored-not-misattributed
  (testing "DA before any SF has no file to belong to"
    (is (= {} (lcov/parse "DA:1,1\n")))))

(deftest an-empty-or-absent-report-parses-to-nothing
  (is (= {} (lcov/parse "")))
  (is (= {} (lcov/parse nil))))

(defspec never-throws-and-never-yields-a-bad-line 400
  (prop/for-all [s gen/string]
    (let [p (lcov/parse s)]
      (every? (fn [[_ lines]]
                (every? (fn [[l h]] (and (integer? l) (integer? h))) lines))
              p))))
