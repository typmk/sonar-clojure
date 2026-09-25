(ns net.typemark.sonar.rules-detection-test
  "The plugin-side invariants over sift's node rules: every rule they emit
  is registered here, and none throws on garbage. The flag/clear pair per
  rule lived here until 2026-08-27 and is sift's own gate now
  (node_rules_test), which this alias still runs."
  (:require [clojure.test :refer [deftest is testing]]
            [net.typemark.sonar.metadata :as metadata]
            [net.typemark.sonar.source-sensor :as sensor]
            [net.typemark.sift :as sift]
            [net.typemark.sift.parse :as parse]
            [net.typemark.sift.regex :as regex]
            [net.typemark.sift.tenancy :as tenancy]
            [net.typemark.sift.tests :as tests]
            [net.typemark.sift.web :as web]))

(def ^:private tenant #"(?i)owner|tenant")

(deftest every-rule-these-rulesets-emit-is-registered
  (testing "an issue raised against an unregistered rule is dropped by the
            scanner without a message"
    (let [declared (set (metadata/all-keys))
          src (str "(defn h [o] (if (nil? (:obj/owner o)) (throw (ex-info \"x\" {})) :ok))\n"
                   "(defn q [db] (d/q '[:find ?e :where [?e :product/sku]] db))\n"
                   "(def p #\"(a{1,9}){1,9}\")\n"
                   "(defn ok? [s] (when (re-find #\"a\\\\.b\" s) :y))\n"
                   "(defn r [x] (h/raw (str x)))\n"
                   "(defn l [auth-token] (log/info \"t\" auth-token))\n"
                   "(def c {:cookies {\"s\" {:value v :max-age 1}}})\n"
                   "(deftest nothing (println :hi))\n"
                   "(deftest t (is (= 1)))\n")
          l (sift/linter {:rulesets #{:security :tests :tenancy}
                          :rules {:tenancy/ambiguous-owner-check {:tenant-pattern "owner|tenant"}
                                  :tenancy/unscoped-tenant-query {:tenant-pattern "owner|tenant"}}})
          emitted (into #{} (map (comp sensor/rule-key :rule))
                        (:findings (sift/lint l [{:path "test/a_test.clj" :text src}])))]
      (is (<= 8 (count emitted)) (pr-str emitted))
      (is (every? declared emitted)
          (str "emitted but not registered: " (pr-str (remove declared emitted)))))))

(deftest none-of-them-throw-on-unparseable-or-empty-input
  (doseq [f [#(tenancy/ambiguous-owner-check % tenant) #(tenancy/unscoped-tenant-query % tenant #{})
             web/xss-unescaped-output web/csrf-protection-absent web/sensitive-data-logged web/cookie-missing-security-flags
             regex/redos-vulnerable-regex regex/partial-match-validation
             tests/empty-test tests/testing-without-assertion tests/test-with-no-effect]
          src ["" "(" ")" "#_" ";; just a comment" "(defn"]]
    (is (nil? (try (doall (f (:nodes (parse/parse src)))) nil
                   (catch Throwable t t)))
        (str "threw on " (pr-str src)))))
