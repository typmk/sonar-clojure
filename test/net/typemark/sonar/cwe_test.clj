(ns net.typemark.sonar.cwe-test
  "The CWE claims are checked against MITRE, not against a reviewer's memory."
  (:require [clojure.edn :as edn]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [net.typemark.sonar.cwe :as cwe]
            [net.typemark.sonar.metadata :as metadata]
            [net.typemark.sonar.provenance :as provenance]))

(defn- claims
  "Every [rule-key cwe-id] this plugin asserts."
  []
  (for [r (metadata/load-rules (metadata/all-keys))
        c (:cwe r)]
    [(:key r) c]))

(deftest the-catalogue-is-the-one-that-was-audited
  (is (= "4.20" (cwe/version))
      "the artifact records which MITRE revision validated its mappings")
  (is (= 969 (count (get @cwe/catalogue "weaknesses")))))

(deftest every-claimed-cwe-exists
  (doseq [[rule c] (claims)]
    (is (some? (cwe/entry c))
        (str rule " claims CWE-" c ", absent from MITRE v" (cwe/version)))))

(deftest no-rule-maps-to-a-weakness-mitre-discourages
  (testing "MITRE's Mapping Notes Usage field is the authority, not our reading
            of the abstraction level"
    (let [bad (keep (fn [[rule c]]
                      (when-let [v (cwe/violation c)] (assoc v :rule rule)))
                    (claims))]
      (is (empty? bad)
          (str "mappings MITRE does not permit: " (pr-str bad))))))

(deftest the-check-can-actually-fail
  (testing "a check that cannot find a violation proves nothing"
    (is (some? (cwe/violation 20))
        "CWE-20 is Discouraged by MITRE; if this passes, the check is inert")
    (is (some? (cwe/violation 999999)) "an absent id is a violation")
    (is (nil? (cwe/violation 327)) "and a legitimate mapping is not")))

(deftest security-rules-carry-a-mapping-at-all
  (let [sec (filter #(contains? #{"VULNERABILITY" "SECURITY_HOTSPOT"} (:type %))
                    (metadata/load-rules (metadata/all-keys)))]
    (is (seq sec))
    (doseq [r sec]
      (is (seq (:cwe r))
          (str (:key r) " is a " (:type r) " with no CWE; the claim is unroutable")))))

(deftest the-recorded-clj-kondo-version-matches-what-is-declared
  (testing "clj-kondo can be upgraded in deps.edn without regenerating the
            catalogue; the two then disagree and nothing says so"
    (let [declared (get-in (edn/read-string (slurp "deps.edn"))
                           [:aliases :gen-rules :extra-deps 'clj-kondo/clj-kondo :mvn/version])]
      (is (= declared @provenance/clj-kondo-version)
          "run `clojure -X:gen-rules` after changing the clj-kondo dependency"))))

(deftest the-summary-reads-its-facts-from-the-artifacts-it-describes
  (testing "nothing is a stored copy, so nothing can disagree with the original"
    (let [s (provenance/summary)]
      (is (str/includes? s (str @provenance/rule-count " rules")))
      (is (str/includes? s (cwe/version)))
      (is (= @provenance/rule-count
             (count (edn/read-string (slurp "resources/net/typemark/sonar/linters.edn"))))))))
