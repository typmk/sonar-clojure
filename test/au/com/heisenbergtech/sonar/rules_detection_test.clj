(ns au.com.heisenbergtech.sonar.rules-detection-test
  "The plugin-side invariants over sift's node rules: every rule they emit
  is registered here, and none throws on garbage. The flag/clear pair per
  rule lived here until 2026-08-27 and is sift's own gate now
  (node_rules_test), which this alias still runs."
  (:require [clojure.test :refer [deftest is testing]]
            [com.typemark.sift.access :as access]
            [au.com.heisenbergtech.sonar.metadata :as metadata]
            [com.typemark.sift.parse :as parse]
            [com.typemark.sift.regex :as regex]
            [com.typemark.sift.tests :as tests]
            [com.typemark.sift.web :as web]))

(defn- rules [f src] (set (map :rule (f (:nodes (parse/parse src))))))

;; The flag/clear pair per rule moved home to sift (test/com/typemark/sift/
;; node_rules_test.clj, 2026-08-27) — that suite runs here too through the
;; :test alias's -d ../sift/test. What stays is what is sonar's: that every
;; rule these namespaces emit is registered in the plugin's metadata.

;; ------------------------------------------------------------ invariants

(deftest every-rule-these-namespaces-emit-is-registered
  (testing "an issue raised against an unregistered rule is dropped by the
            scanner without a message"
    (let [declared (set (metadata/all-keys))
          emitted  (into #{}
                         (mapcat (fn [[f src]] (rules f src)))
                         [[access/findings "(defn h [o] (if (nil? (:obj/owner o)) (throw (ex-info \"x\" {})) :ok))"]
                          [access/findings "(d/q '[:find ?e :where [?e :product/sku]] db)"]
                          [access/findings "(def p {:party/platform-role :admin})"]
                          [regex/findings  "(def p #\"(a{1,9}){1,9}\")"]
                          [regex/findings  "(defn ok? [s] (when (re-find #\"a\\\\.b\" s) :y))"]
                          [web/findings    "(h/raw (str x))"]
                          [web/findings    "(log/info \"t\" auth-token)"]
                          [web/findings    "(def c {:cookies {\"s\" {:value v :max-age 1}}})"]
                          [tests/findings  "(deftest nothing (println :hi))"]
                          [tests/findings  "(deftest t (is (= 1)))"]])]
      (is (seq emitted))
      (is (every? declared emitted)
          (str "emitted but not registered: " (pr-str (remove declared emitted)))))))

(deftest none-of-them-throw-on-unparseable-or-empty-input
  (doseq [f [access/findings web/findings regex/findings tests/findings]
          src ["" "(" ")" "#_" ";; just a comment" "(defn"]]
    (is (nil? (try (doall (f (:nodes (parse/parse src)))) nil
                   (catch Throwable t t)))
        (str "threw on " (pr-str src)))))

;; ---------------------------------------------------------------- interop
