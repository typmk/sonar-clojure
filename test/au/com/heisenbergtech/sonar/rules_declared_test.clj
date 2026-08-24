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
  (:require [clojure.test :refer [deftest is]]
            [au.com.heisenbergtech.sonar.metadata :as metadata]
            [com.typemark.sift.security :as security]))

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
    (is (every? declared (map :rule (security/findings-of-source src)))
        "a finding whose rule is not registered would be dropped by Sonar")))
