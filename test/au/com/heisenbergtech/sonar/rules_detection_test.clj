(ns au.com.heisenbergtech.sonar.rules-detection-test
  "The four rule namespaces the sensor composes but no test reached.

  Measured before this file existed: access 7.9% of forms, web 6.7%,
  regex 8.8%, tests 5.6%. They are composed in `source-sensor`, not in
  `security/findings-of-source`, so the existing security suite ran straight
  past them.

  Twelve rules had therefore never been executed against a case they should
  catch or a case they must not. That is precisely how this ruleset has failed
  before: `redos-vulnerable-regex` scored 0 true positives out of 11 when it
  was finally measured, and `permissive-file-permissions` fired on 0700 while
  ignoring 0666.

  So every rule gets both. A positive alone proves a rule can fire, which a
  rule matching everything also does."
  (:require [clojure.test :refer [deftest is testing]]
            [au.com.heisenbergtech.scan.access :as access]
            [au.com.heisenbergtech.scan.interop :as interop]
            [au.com.heisenbergtech.sonar.metadata :as metadata]
            [au.com.heisenbergtech.scan.parse :as parse]
            [au.com.heisenbergtech.scan.regex :as regex]
            [au.com.heisenbergtech.scan.tests :as tests]
            [au.com.heisenbergtech.scan.web :as web]))

(defn- rules [f src] (set (map :rule (f (:nodes (parse/parse src))))))

(defn- fires
  "Asserts `rule` is raised for `bad` and not for `good` -- the pair, always."
  [f rule bad good]
  (is (contains? (rules f bad) rule) (str rule " missed: " (pr-str bad)))
  (is (not (contains? (rules f good) rule))
      (str rule " false positive on: " (pr-str good))))

;; ---------------------------------------------------------------- access

(deftest ambiguous-owner-check
  (testing "WEB-184's actual shape: nil owner means both untenanted and
            unresolved, and a two-valued test sends both down one branch"
    (fires access/findings "ambiguous-owner-check"
           "(defn h [o] (if (nil? (:obj/owner o)) (throw (ex-info \"no\" {})) :ok))"
           "(defn h [o] (case (owner-of o) ::unresolved (throw (ex-info \"no\" {})) :ok))")))

(deftest unscoped-tenant-query
  (fires access/findings "unscoped-tenant-query"
         "(d/q '[:find ?e :where [?e :product/sku]] db)"
         "(d/q '[:find ?e :in $ ?owner :where [?e :obj/owner ?owner]] db o)"))

(deftest operator-as-party
  (testing "the operator invariant: access is an off-graph staff fact, never a
            party attribute -- blindness enforced by absence"
    (fires access/findings "operator-as-party"
           "(def p {:party/platform-role :admin})"
           "(def p {:party/uuid id})")))

;; ----------------------------------------------------------------- regex

(deftest redos-vulnerable-regex
  (testing "brace-nested quantifiers, the shape that actually backtracks"
    (fires regex/findings "redos-vulnerable-regex"
           "(def p #\"(a{1,9}){1,9}\")"
           "(def p #\"^[a-z]+$\")")))

(deftest partial-match-validation
  (testing "re-find succeeds on a PARTIAL match, so an unanchored pattern in a
            decision position accepts anything containing a match"
    (fires regex/findings "partial-match-validation"
           "(defn ok? [s] (when (re-find #\"good\\\\.example\" s) :yes))"
           "(defn ok? [s] (when (re-find #\"^good$\" s) :yes))")))

;; ------------------------------------------------------------------- web

(deftest xss-unescaped-output
  (testing "hiccup's raw exists to bypass escaping; a literal argument is the
            reason it exists, a computed one is the weakness"
    (fires web/findings "xss-unescaped-output"
           "(h/raw (str \"<b>\" x \"</b>\"))"
           "(h/raw \"<hr>\")")))

(deftest csrf-protection-absent
  (fires web/findings "csrf-protection-absent"
         "(ns app.routes (:require [reitit.ring :as ring]))\n(def routes [[\"/pay\" {:post handler}]])"
         (str "(ns app.routes (:require [reitit.ring :as ring]"
              " [ring.middleware.anti-forgery :as af]))\n"
              "(def routes [[\"/pay\" {:post handler}]])")))

(deftest sensitive-data-logged
  (fires web/findings "sensitive-data-logged"
         "(log/info \"tok\" auth-token)"
         "(log/info \"count\" n)"))

(deftest cookie-missing-security-flags
  (fires web/findings "cookie-missing-security-flags"
         "(def c {:cookies {\"sid\" {:value v :max-age 3600}}})"
         "(def c {:cookies {\"sid\" {:value v :max-age 3600 :http-only true :secure true}}})"))

;; ----------------------------------------------------------------- tests

(deftest empty-test
  (testing "a test that asserts nothing passes whatever the code does, which
            is worse than having no test because it reports as coverage"
    (fires tests/findings "empty-test"
           "(deftest nothing (println :hi))"
           "(deftest something (is (= 1 1)))")))

(deftest empty-test-understands-assertion-helpers
  (testing "found by dogfooding: this very namespace asserts through `fires`,
            and the rule raised 19 findings against it, every one wrong"
    (is (empty? (rules tests/findings
                       "(defn- fires [a b] (is (= a b)))\n(deftest x (testing \"t\" (fires 1 1)))"))
        "a deftest delegating to a helper that asserts is not an empty test"))
  (testing "and a helper that asserts nothing still does not rescue it"
    (is (contains? (rules tests/findings "(defn- noop [a] a)\n(deftest x (noop 1))")
                   "empty-test"))))

(deftest testing-without-assertion
  (fires tests/findings "testing-without-assertion"
         "(deftest t (is (= 1 1)) (testing \"nothing\" (println :x)))"
         "(deftest t (testing \"ok\" (is (= 1 1))))"))

(deftest test-with-no-effect
  (testing "(= x) with one operand is always true"
    (fires tests/findings "test-with-no-effect"
           "(deftest t (is (= 1)))"
           "(deftest t (is (= 1 1)))")))

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

(deftest jndi-injection
  (testing "the only one of the nine unexercised rules that is plugin-side
            rather than a clj-kondo hook. It fires on the STATIC form"
    (fires interop/findings "jndi-injection"
           "(defn look [n] (javax.naming.InitialContext/doLookup n))"
           "(defn look [] (javax.naming.InitialContext/doLookup \"java:comp/env\"))"))
  (testing "and NOT on the instance form, which is the commoner one. Measured:
            (.lookup ctx n), (.lookup (InitialContext.) n) and a ^Context type
            hint all produce nothing. Detecting them needs to know the type of
            the receiver, and this plugin has no type inference -- so the rule
            covers a real shape rather than the whole weakness, and saying
            otherwise would overstate what a JNDI scan here is worth"
    (is (empty? (rules interop/findings "(defn look [n] (.lookup ctx n))")))
    (is (empty? (rules interop/findings
                       "(defn look [n] (.lookup (javax.naming.InitialContext.) n))")))))

(deftest unscoped-tenant-query-precision
  (testing "fires on a tenanted scan with no owner named"
    (fires access/findings "unscoped-tenant-query"
           "(d/q '[:find ?e :where [?e :document/type :invoice]] db)"
           "(d/q '[:find ?e :in $ ?owner :where [?e :document/type :invoice] [?e :obj/owner ?owner]] db owner)"))
  (testing "a pull takes an entity id the caller already holds, so it is not an
            unscoped scan -- the tenancy question belongs where that id came
            from. Measured: pulls were 40 of 124 findings on lume, sur and
            forma, and not one was a scan"
    (is (empty? (rules access/findings "(d/pull db '[*] eid)")))
    (is (empty? (rules access/findings "(pull db '[*] eid)"))))
  (testing "the taxonomy and compat layer classifies product DEFINITIONS and is
            the same for every tenant, so a query touching only it has no
            tenant to name. It was the largest false-positive class"
    (is (empty? (rules access/findings "(d/q '[:find ?e :where [?e :taxon/factor _]] db)")))
    (is (empty? (rules access/findings
                       "(d/q '[:find ?a ?b :where [?a :std/carries ?b] [?a :conn/adapts ?b]] db)"))))
  (testing "a query naming no attribute at all says nothing either way, and the
            safer reading is to keep it"
    (is (contains? (rules access/findings "(d/q query db)") "unscoped-tenant-query"))))
