(ns net.typemark.sonar.coverage-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [net.typemark.sonar.coverage :as coverage]))

(def report
  "{\"src/a.clj\":[null,3,true,0,null,7],\"src/b.clj\":[null,0]}")

(deftest partial-coverage-survives
  (let [p (coverage/parse report)]
    (is (= {1 {:hits 3 :partial? false}
            2 {:hits 1 :partial? true}
            3 {:hits 0 :partial? false}
            5 {:hits 7 :partial? false}}
           (get p "src/a.clj")))
    (testing "a blank line is absent, not recorded as uncovered"
      (is (not (contains? (get p "src/a.clj") 4))))))

(deftest instrumented-lines-are-ground-truth-for-executable-data
  (is (= {"src/a.clj" #{1 2 3 5} "src/b.clj" #{1}}
         (coverage/instrumented-lines (coverage/parse report)))))

(deftest a-report-that-is-not-codecov-yields-nothing
  (is (nil? (coverage/parse "")))
  (is (nil? (coverage/parse nil)))
  (testing "lcov, which would read partial lines as covered"
    (is (nil? (coverage/parse "SF:src/a.clj\nDA:1,1\nend_of_record\n"))))
  (is (nil? (coverage/parse "[1,2]"))))

(defspec never-throws-on-arbitrary-input 200
  (prop/for-all [s gen/string]
    (let [p (coverage/parse s)] (or (nil? p) (map? p)))))

(deftest an-exact-key-wins-over-a-suffix
  (is (= :exact (coverage/lines-for {"src/a/b.clj" :exact "a/b.clj" :suffix} "src/a/b.clj"))))

(deftest a-key-without-the-source-root-still-matches
  (is (= :hit (coverage/lines-for {"a/b.clj" :hit} "/work/src/a/b.clj"))))

(deftest a-suffix-matches-only-at-a-path-separator
  (is (nil? (coverage/lines-for {"b.clj" :wrong} "/work/src/a/megab.clj"))))
