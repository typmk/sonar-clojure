(ns net.typemark.sonar.coverage-test
  (:require [clojure.test :refer [deftest is]]
            [net.typemark.sonar.coverage :as coverage]))

(deftest an-exact-key-wins-over-a-suffix
  (is (= :exact (coverage/lines-for {"src/a/b.clj" :exact "a/b.clj" :suffix} "src/a/b.clj"))))

(deftest a-key-without-the-source-root-still-matches
  (is (= :hit (coverage/lines-for {"a/b.clj" :hit} "/work/src/a/b.clj"))))

(deftest a-suffix-matches-only-at-a-path-separator
  (is (nil? (coverage/lines-for {"b.clj" :wrong} "/work/src/a/megab.clj"))))
