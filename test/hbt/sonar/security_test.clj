(ns hbt.sonar.security-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [hbt.sonar.security :as security]))

(defn- rules-for [src] (set (map :rule (security/findings-of-source src))))
(defn- finding-for [src rule]
  (first (filter #(= rule (:rule %)) (security/findings-of-source src))))

(deftest detects-injection-shapes
  (is (contains? (rules-for "(eval (read-string x))") "eval-of-dynamic-value"))
  (is (contains? (rules-for "(eval (read-string x))") "read-string-untrusted"))
  (is (contains? (rules-for "(sh \"sh\" \"-c\" cmd)") "shell-command-injection"))
  (is (contains? (rules-for "(jdbc/query db (str \"select \" x))") "sql-string-built")))

(deftest detects-hardcoded-secrets
  ;; weak-hash-algorithm and insecure-random live in hbt.sonar.interop now:
  ;; resolving the class beats matching the string "MD5" wherever it appears.
  (is (contains? (rules-for "(def api-key \"sk-live-abcdef\")") "hardcoded-credential")))

(deftest distinguishes-a-defect-from-a-thing-to-review
  (testing "a shell call with only literal arguments is a hotspot, not a bug"
    (is (contains? (rules-for "(sh \"ls\" \"-la\")") "shell-invocation"))
    (is (not (contains? (rules-for "(sh \"ls\" \"-la\")") "shell-command-injection"))))
  (testing "a shell call carrying a computed argument is the defect"
    (is (contains? (rules-for "(sh \"sh\" \"-c\" user-input)") "shell-command-injection"))))

(deftest links-source-to-sink
  (let [f (finding-for "(let [n (slurp url)] (sh \"sh\" \"-c\" n))" "shell-command-injection")]
    (is (some? f))
    (testing "the flow names where the value came from, not just where it landed"
      (is (= 2 (count (:flow f))))
      (is (re-find #"originates" (:message (first (:flow f)))))
      (is (re-find #"reaches the sink" (:message (second (:flow f))))))))

(deftest ring-request-access-is-a-source
  (let [f (finding-for "(let [q (:params req)] (eval q))" "eval-of-dynamic-value")]
    (is (some? f) "(:params req) must count as attacker-influenced")
    (is (seq (:flow f)))))

;; The honest bound on what this can claim.
(deftest states-its-own-limits
  (testing "commented-out code is not a finding"
    (is (empty? (rules-for "#_(eval (read-string x))")))
    (is (empty? (rules-for "(comment (sh \"sh\" \"-c\" x))"))))
  (testing "a literal eval is not flagged -- nothing computed reaches it"
    (is (not (contains? (rules-for "(eval '(inc 1))") "eval-of-dynamic-value"))))
  (testing "a short literal is not treated as a credential"
    (is (not (contains? (rules-for "(def token \"x\")") "hardcoded-credential"))))
  (testing "the credential name is matched on segment boundaries -- `bypass`
            is not `pass`, and a rule that cries wolf gets ignored"
    (doseq [nm ["*jvm-wide-hostname-bypass-permitted?*" "tokenizer" "compass" "passthrough"]]
      (is (not (contains? (rules-for (str "(def " nm " \"aaaaaaaaaa\")")) "hardcoded-credential"))
          nm))
    (doseq [nm ["api-key" "db-password" "client-secret" "auth-token"]]
      (is (contains? (rules-for (str "(def " nm " \"aaaaaaaaaa\")")) "hardcoded-credential")
          nm)))
  (testing "interprocedural taint is OUT OF SCOPE and must not be claimed:
            a source in one fn reaching a sink in another produces the sink
            finding, but no flow"
    (let [f (finding-for "(defn a [] (slurp url))\n(defn b [x] (sh \"sh\" \"-c\" x))"
                         "shell-command-injection")]
      (is (some? f) "the sink is still reported")
      (is (nil? (:flow f)) "but no flow is invented across the call boundary"))))

(deftest seeds-agree-with-the-direct-rules-about-what-danger-is
  (testing "a parameterised query is NOT a sink -- it was seeding the
            interprocedural pass and producing six false paths in lume"
    (let [s (security/seeds-of-source
             "(ns a)\n(defn f [org-id]\n  (jdbc/execute! ds [\"select * from t where org = ?\" org-id]))")]
      (is (empty? (:reaches s)))))
  (testing "a query built by string concatenation IS"
    (let [s (security/seeds-of-source
             "(ns a)\n(defn f [x]\n  (jdbc/query db (str \"select \" x)))")]
      (is (= #{["a" "f"]} (:reaches s)))))
  (testing "a shell call with only literal args is not a sink either"
    (is (empty? (:reaches (security/seeds-of-source "(ns a)\n(defn f [] (sh \"ls\"))")))))
  (testing "and a source is picked up under its enclosing var"
    (is (= #{["a" "g"]}
           (:taints (security/seeds-of-source "(ns a)\n(defn g [req] (:params req))"))))))

(deftest every-rule-emitted-is-a-declared-rule
  (let [declared (set (map :key security/rules))
        src "(def password \"hunter2hunter2\")
             (eval (read-string (:params req)))
             (sh \"sh\" \"-c\" (slurp u))
             (jdbc/query db (str \"x\" y))
             (java.util.Random.)
             (MessageDigest/getInstance \"MD5\")
             (resolve (symbol s))
             (xml/parse s)"]
    (is (every? declared (map :rule (security/findings-of-source src)))
        "a finding whose rule is not registered would be dropped by Sonar")))

;; This runs over every file in the project. A throw costs the whole file's
;; measures, not just its security findings.
(defspec never-throws-on-arbitrary-source 300
  (prop/for-all [s gen/string]
    (let [r (security/findings-of-source s)]
      (or (nil? r) (vector? r)))))

(defspec every-finding-has-a-usable-range 300
  (prop/for-all [s gen/string-alphanumeric]
    (every? (fn [f] (and (>= (:line f) 1) (>= (:col f) 1)
                         (> (:end-col f) 0)))
            (or (security/findings-of-source s) []))))
