(ns au.com.heisenbergtech.sonar.rules-declared-test
  "Every rule sift emits must be one this plugin declares.

  It lived in sift's own security_test until sift was published as a
  standalone repo. It could not stay: the assertion needs
  `au.com.heisenbergtech.sonar.metadata`, which is this repository, so a clone
  of sift alone could not run its own suite — the one test that reached across
  the split made the other twenty-three unrunnable.

  The claim is about SONAR, not about the rules. A finding whose rule key is
  not registered is dropped by the scanner without a word, so the failure mode
  is a rule that runs, matches, and produces nothing anyone sees."
  (:require [clojure.test :refer [deftest is testing]]
            [au.com.heisenbergtech.sonar.metadata :as metadata]
            [au.com.heisenbergtech.sonar.source-sensor :as sensor]
            [net.typemark.sift :as sift]))

(defn- emitted [rulesets src]
  (map :rule (:findings (sift/lint (sift/linter {:rulesets rulesets}) [{:path "src/a.clj" :text src}]))))

(deftest every-rule-emitted-is-a-declared-rule
  (let [declared (set (metadata/all-keys))
        src "(def password \"hunter2hunter2\")
             (eval (read-string (:params req)))
             (sh \"sh\" \"-c\" (slurp u))
             (jdbc/query db (str \"x\" y))
             (java.util.Random.)
             (MessageDigest/getInstance \"MD5\")
             (resolve (symbol s))
             (xml/parse s)"]
    (is (every? declared (map sensor/rule-key (emitted #{:security} src)))
        "a finding whose rule is not registered would be dropped by Sonar")))

(deftest every-prose-rule-emitted-is-a-declared-rule
  (testing "prose findings carry a keyword rule; the sensor's rule-key makes
            it the string Sonar knows, and that string must be registered.
            Before 2026-08-31 neither held: the keyword failed RuleKey/of and
            no :doc/* rule shipped, so every prose finding was dropped."
    (let [declared (set (metadata/all-keys))
          src (str "(ns a)\n"
                   "(defn parse-config \"Parses the config.\" [x] x)\n"
                   "(defn merge-rows \"This function is used for combining. TODO\" [left right] [left right])\n")
          rules (distinct (map :rule (:findings (sift/lint (sift/linter {:rulesets #{:doc} :rules {:doc/ns-missing :warning}})
                                                           [{:path "src/a.clj" :text src}]))))]
      (is (= #{:doc/restates-name :doc/hedge :doc/placeholder :doc/params-unnamed :doc/ns-missing} (set rules))
          "the fixture must trip all five, or the assertion below is vacuous for the ones it misses")
      (is (every? declared (map sensor/rule-key rules))
          "a prose rule whose string key is not registered is dropped by Sonar"))))
