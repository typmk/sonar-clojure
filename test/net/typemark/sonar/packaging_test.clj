(ns net.typemark.sonar.packaging-test
  "The jar's identity claims, checked against the jar.

  Everything here fails at deploy time rather than at build time, and fails
  quietly: a Plugin-Class naming a class the rename left behind produces a
  plugin SonarQube loads and ignores, and the operator sees a language that
  simply is not there. The suite is the only place this gets caught early."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [net.typemark.sonar.const :as const])
  (:import [java.util.jar JarFile]))

(def ^:private jar
  (delay (first (filter #(re-matches #"sonar-clojure-plugin-.*\.jar" (.getName %))
                        (.listFiles (io/file "target"))))))

(defn- attrs []
  (with-open [j (JarFile. ^java.io.File @jar)]
    (into {} (for [[k v] (.getMainAttributes (.getManifest j))] [(str k) v]))))

(defn- entries []
  (with-open [j (JarFile. ^java.io.File @jar)]
    (set (map #(.getName %) (enumeration-seq (.entries j))))))

(deftest the-jar-under-test-exists
  (testing "every other test here guards on the jar, so without this one their
            absence would read as their passing"
    (is (some? @jar)
        "no jar in target/ -- run `clojure -T:build uber` before the suite")))

(deftest the-entry-point-the-manifest-names-is-in-the-jar
  (testing "a Plugin-Class the build renamed away loads as a plugin that does
            nothing, with no error the operator ever sees"
    (when @jar
      (let [cls (get (attrs) "Plugin-Class")]
        (is (= "net.typemark.sonar.ClojurePluginBootstrap" cls))
        (is (contains? (entries) (str (str/replace cls "." "/") ".class")))))))

(deftest the-resources-the-plugin-loads-are-in-the-jar
  (testing "every required-resource path is package-scoped, so a package
            rename moves them or breaks them -- there is no third outcome"
    (when @jar
      (doseq [r [const/cwe-resource
                 const/linters-resource
                 const/provenance-resource
                 "org/sonar/l10n/clj/rules/clj-kondo/index.edn"]]
        (is (contains? (entries) r) (str r " missing from the jar"))))))

(deftest sonarsources-own-layout-is-not-renamed-with-ours
  (testing "org/sonar/l10n is SonarSource's path, not ours; moving it with the
            package would leave every rule without a description"
    (when @jar
      (is (some #(str/starts-with? % "org/sonar/l10n/clj/rules/") (entries)))
      (is (not-any? #(str/includes? % "net/typemark/sonar/l10n") (entries))))))

(deftest the-api-is-provided-not-bundled
  (testing "bundling sonar-plugin-api makes the scanner load two copies of every
            interface and every extension fails an instanceof check"
    (when @jar
      (is (not-any? #(str/starts-with? % "org/sonar/api/") (entries))))))

(deftest the-build-says-whether-it-came-from-committed-code
  (when @jar
    (let [a (attrs)]
      (is (re-matches #"[0-9a-f]{40}" (get a "Build-Revision")))
      (is (contains? #{"clean" "dirty"} (get a "Build-Status")))
      (is (str/starts-with? (get a "Implementation-Version")
                            (str (get a "Plugin-Version") "+"))
          "the version must name the commit it was built from"))))

(deftest a-checksum-is-published-beside-the-jar
  (testing "SonarQube does not verify a dropped-in plugin, so integrity at
            deploy time is only whatever the operator can check by hand"
    (when @jar
      (let [sum (io/file (str @jar ".sha256"))]
        (is (.isFile sum))
        (is (re-find (re-pattern (.getName ^java.io.File @jar)) (slurp sum)))))))

(deftest the-two-coverage-exclusion-lists-agree
  (testing "cloverage excludes namespaces; Sonar excludes paths. Two lists for
            one decision drift, and the symptom is a dashboard that disagrees
            with the report it was given -- measured once at 52.2% against 73.9%"
    (let [nses (->> (re-find #"net\.typemark\.sonar\.\(([^)]+)\)" (slurp "deps.edn"))
                    second
                    (#(str/split % #"\|"))
                    (map #(str/replace % "-" "_"))
                    set)
          paths (->> (slurp "sonar-project.properties")
                     (re-find #"(?s)sonar\.coverage\.exclusions=(.*?)\n\n|(?s)sonar\.coverage\.exclusions=(.*)$")
                     (drop 1) (some identity)
                     (re-seq #"sonar/(\w+)\.clj")
                     (map second) set)]
      (is (seq nses))
      (is (= nses paths)
          (str "only in deps.edn: " (pr-str (remove paths nses))
               "; only in sonar-project.properties: " (pr-str (remove nses paths)))))))
