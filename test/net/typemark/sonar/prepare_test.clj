(ns net.typemark.sonar.prepare-test
  "`prepare` against a real clj-kondo, in a fresh project. The claim is the
  whole chain: the hooks land where clj-kondo loads them, so a hook rule
  fires in the one report, and that report carries the analysis the plugin
  reads as a second input."
  (:require [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [net.typemark.sonar.prepare :as prepare])
  (:import [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]))

(defn- temp-dir ^java.io.File []
  (.toFile (Files/createTempDirectory "prepare" (into-array FileAttribute []))))

(deftest one-command-writes-the-report-the-plugin-reads
  (let [dir (temp-dir)]
    (spit (doto (io/file dir "src/a.clj") io/make-parents)
          "(ns a (:import [java.security MessageDigest]))\n(defn h [] (MessageDigest/getInstance \"MD5\"))\n")
    (let [printed (with-out-str (prepare/prepare {:dir (str dir)}))
          report (json/read-str (slurp (io/file dir "target/clj-kondo.json")))]
      (testing "the hooks are installed where clj-kondo loads them"
        (is (.isDirectory (io/file dir ".clj-kondo/imports/net.typemark/sonar-clojure"))))
      (testing "a hook rule fires, so the hooks were loaded, not merely copied"
        (is (some #(= "typemark/weak-hash-algorithm" (get % "type")) (get report "findings"))
            (pr-str (map #(get % "type") (get report "findings")))))
      (testing "one run carries the analysis too"
        (is (seq (get-in report ["analysis" "var-definitions"]))))
      (testing "what the project has not produced is named, with how to produce it"
        (is (str/includes? printed "missing   cloverage coverage"))
        (is (str/includes? printed "missing   kaocha test execution"))
        (is (not (str/includes? printed "missing   clj-kondo")))))))
