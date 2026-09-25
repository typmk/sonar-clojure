(ns net.typemark.sonar.rules-declared-test
  "Every rule sift emits must be one this plugin declares.

  It lived in sift's own security_test until sift was published as a
  standalone repo. It could not stay: the assertion needs
  `net.typemark.sonar.metadata`, which is this repository, so a clone
  of sift alone could not run its own suite — the one test that reached across
  the split made the other twenty-three unrunnable.

  The claim is about SONAR, not about the rules. A finding whose rule key is
  not registered is dropped by the scanner without a word, so the failure mode
  is a rule that runs, matches, and produces nothing anyone sees."
  (:require [clojure.test :refer [deftest is testing]]
            [net.typemark.sonar.metadata :as metadata]
            [net.typemark.sonar.source-sensor :as sensor]
            [net.typemark.sift :as sift]
            [net.typemark.sift.registry :as registry]))

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
    (is (every? declared (map metadata/rule-key (emitted #{:security} src)))
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
      (is (every? declared (map metadata/rule-key rules))
          "a prose rule whose string key is not registered is dropped by Sonar"))))

(deftest every-sift-rule-a-scan-can-run-is-registered
  (testing "a sift rule with no Sonar entry was computed on every scan and
            its findings dropped -- 26 were, until 2026-09-25. Rules needing
            the host-compiler oracle are the exception: a scan never has one."
    (let [declared (set (metadata/all-keys))]
      (doseq [r registry/built-in :when (not (contains? (:needs r) :oracle))]
        (is (declared (metadata/rule-key (:id r))) (str (:id r) " is not registered"))))))

(deftest the-profile-decides-what-sift-runs
  (let [run (fn [active] (-> (sensor/sift-config active) :config sift/linter sift/rules
                             (->> (map :id) set)))]
    (testing "nothing active, nothing computed"
      (is (empty? (run #{}))))
    (testing "an active rule runs, and only it"
      (is (= #{:style/let-as-thread} (run #{"let-as-thread"}))))
    (testing "a rule sift defaults to :off runs when the profile turns it on"
      (is (= #{:doc/ns-missing} (run #{"doc-ns-missing"}))))
    (testing "a rule whose options Sonar cannot supply is reported, not run"
      (let [{:keys [config unconfigured]} (sensor/sift-config #{"unscoped-tenant-query"})]
        (is (= [:tenancy/unscoped-tenant-query] unconfigured))
        (is (empty? (sift/rules (sift/linter config))))))))
