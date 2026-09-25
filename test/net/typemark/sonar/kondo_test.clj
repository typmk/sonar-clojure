(ns net.typemark.sonar.kondo-test
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [net.typemark.sonar.const :as const]
            [net.typemark.sonar.kondo :as kondo]))

(def report
  (str "{\"findings\":["
       "{\"end-row\":2,\"type\":\"unused-binding\",\"level\":\"warning\","
       "\"filename\":\"probe.clj\",\"col\":19,\"end-col\":20,\"langs\":[],"
       "\"message\":\"unused binding y\",\"row\":2},"
       "{\"end-row\":3,\"type\":\"type-mismatch\",\"level\":\"error\","
       "\"filename\":\"probe.clj\",\"col\":6,\"end-col\":9,\"langs\":[],"
       "\"message\":\"Expected: number, received: string.\",\"row\":3}],"
       "\"summary\":{\"error\":1,\"warning\":1,\"info\":0,\"type\":\"summary\",\"duration\":17,\"files\":1}}"))

(deftest parses-the-real-report-shape
  (let [fs (kondo/findings report)]
    (is (= 2 (count fs)))
    (is (= {:filename "probe.clj" :type "unused-binding" :level "warning"
            :message "unused binding y" :row 2 :col 19 :end-row 2 :end-col 20}
           (first fs)))))

(deftest columns-convert-to-sonar-offsets
  (testing "clj-kondo col 6 is Sonar offset 5"
    (is (= {:line 3 :start-offset 5 :end-line 3 :end-offset 8}
           (kondo/span {:row 3 :col 6 :end-row 3 :end-col 9}))))
  (testing "a zero-width span degrades to the whole line rather than an invalid range"
    (is (kondo/whole-line? (kondo/span {:row 3 :col 6 :end-row 3 :end-col 6}))))
  (testing "a finding with no end position selects its line"
    (is (= {:line 7} (kondo/span {:row 7 :col 2}))))
  (testing "a finding with no position at all still lands on line 1"
    (is (= {:line 1} (kondo/span {})))))

(deftest an-unrecognised-linter-is-filed-not-dropped
  (let [known #{"unused-binding" const/unknown-rule}]
    (testing "a known linter keeps its key and message"
      (is (= {:rule "unused-binding" :message "m" :recognised? true}
             (kondo/classify known {:type "unused-binding" :message "m"}))))
    (testing "an unknown one files under the catch-all, naming itself"
      (let [c (kondo/classify known {:type "from-the-future" :message "m"})]
        (is (= const/unknown-rule (:rule c)))
        (is (false? (:recognised? c)))
        (is (re-find #"from-the-future" (:message c)))))))

(deftest every-exported-hook-lands-on-a-registered-rule
  (testing "the export's linter keys, the prefix the plugin strips, and the
            rules Sonar registers are three spellings of one set; a hook key
            outside the prefix files under the catch-all, and one with no
            registered rule is dropped by the scanner"
    (let [exported (-> (io/resource "clj-kondo.exports/net.typemark/sonar-clojure/config.edn")
                       slurp edn/read-string :linters keys)
          registered (set (edn/read-string
                           (slurp (io/resource "org/sonar/l10n/clj/rules/clj-kondo/index.edn"))))]
      (is (seq exported))
      (doseq [k exported
              :let [rule (kondo/hook-rule (str (namespace k) "/" (name k)))]]
        (is (some? rule) (str k " is outside " const/hook-linter-prefix))
        (is (contains? registered rule) (str rule " has no registered rule")))
      (is (= {:rule "weak-hash-algorithm" :message "m" :recognised? true}
             (kondo/classify registered {:type "typemark/weak-hash-algorithm" :message "m"}))))))

(def gen-finding
  (gen/hash-map :row     (gen/one-of [(gen/choose -5 500) (gen/return nil)])
                :col     (gen/one-of [(gen/choose -5 500) (gen/return nil)])
                :end-row (gen/one-of [(gen/choose -5 500) (gen/return nil)])
                :end-col (gen/one-of [(gen/choose -5 500) (gen/return nil)])))

(defspec span-never-emits-coordinates-sonar-rejects 500
  (prop/for-all [f gen-finding]
    (let [s (kondo/span f)]
      (and (>= (:line s) 1)
           (or (kondo/whole-line? s)
               (and (>= (:start-offset s) 0)
                    (>= (:end-offset s) 0)
                    (>= (:end-line s) (:line s))))))))

(defspec every-finding-is-filed-under-some-rule 200
  (prop/for-all [t (gen/one-of [gen/string-alphanumeric (gen/return nil)])]
    (let [c (kondo/classify #{"known"} {:type t :message "m"})]
      (some? (:rule c)))))
