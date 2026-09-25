(ns net.typemark.sonar.junit-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [net.typemark.sonar.junit :as junit]))

(def report
  (str "<?xml version=\"1.0\"?>\n"
       "<testsuites>"
       "<testsuite name=\"hbt.sur.deploy-test\" tests=\"3\">"
       "  <testcase classname=\"hbt.sur.deploy-test\" name=\"plan-rolling\" time=\"0.012\"/>"
       "  <testcase classname=\"hbt.sur.deploy-test\" name=\"plan-rollback\" time=\"0.008\">"
       "    <failure message=\"boom\">detail</failure>"
       "  </testcase>"
       "  <testcase classname=\"hbt.sur.deploy-test\" name=\"skipped-one\" time=\"0\">"
       "    <skipped/>"
       "  </testcase>"
       "</testsuite>"
       "<testsuite name=\"hbt.sur.effect-test\" tests=\"1\">"
       "  <testcase classname=\"hbt.sur.effect-test\" name=\"ids\" time=\"1.5\">"
       "    <error message=\"nope\">trace</error>"
       "  </testcase>"
       "</testsuite>"
       "</testsuites>"))

(deftest aggregates-per-namespace
  (let [p (junit/parse report)]
    (is (= #{"hbt.sur.deploy-test" "hbt.sur.effect-test"} (set (keys p))))
    (is (= {:tests 3 :failures 1 :errors 0 :skipped 1 :duration-ms 20}
           (get p "hbt.sur.deploy-test")))
    (is (= {:tests 1 :failures 0 :errors 1 :skipped 0 :duration-ms 1500}
           (get p "hbt.sur.effect-test")))))

(deftest totals-across-the-run
  (is (= {:tests 4 :failures 1 :errors 1 :skipped 1 :duration-ms 1520}
         (junit/totals (junit/parse report)))))

(deftest namespace-maps-to-its-source-path
  (testing "dots become directories, hyphens become underscores"
    (is (= "hbt/sur/deploy_test" (junit/ns->path "hbt.sur.deploy-test")))
    (is (= "net/typemark/sonar/parse_test" (junit/ns->path "net.typemark.sonar.parse-test")))))

(deftest an-absent-or-empty-report-yields-nothing
  (is (nil? (junit/parse "")))
  (is (nil? (junit/parse nil))))

(deftest external-entities-are-refused
  (let [xxe (str "<?xml version=\"1.0\"?>"
                 "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
                 "<testsuites><testsuite name=\"a\">"
                 "<testcase classname=\"a\" name=\"&xxe;\" time=\"0\"/>"
                 "</testsuite></testsuites>")]
    (is (thrown? Exception (junit/parse xxe))
        "a doctype declaration must be rejected, not resolved")))

(defspec never-throws-on-non-xml-input 200
  (prop/for-all [s gen/string-alphanumeric]
    (try (junit/parse s) true
         (catch Exception _ true))))
