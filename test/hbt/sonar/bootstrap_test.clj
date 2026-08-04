(ns hbt.sonar.bootstrap-test
  "The Java entry point exists because Clojure's runtime resolves
  clojure/core.clj through the thread context classloader, which inside
  SonarQube's plugin container is the web application's and cannot see the
  plugin jar. Measured on SonarQube 26.7: the server enters a restart loop.

  A cold RT initialisation cannot be reproduced in a JVM that has already
  loaded Clojure, so what is asserted here is the contract the shim must
  honour -- it swaps the loader, delegates, and puts the loader back."
  (:require [clojure.test :refer [deftest is testing]])
  (:import [org.sonar.api Plugin Plugin$Context SonarEdition SonarProduct
            SonarQubeSide SonarRuntime]
           [org.sonar.api.utils Version]))

(defn- runtime ^SonarRuntime []
  (reify SonarRuntime
    (getApiVersion [_] (Version/parse "13.9"))
    (getProduct [_] SonarProduct/SONARQUBE)
    (getSonarQubeSide [_] SonarQubeSide/SCANNER)
    (getEdition [_] SonarEdition/COMMUNITY)))

(defn- bootstrap ^Plugin []
  (-> (Class/forName "hbt.sonar.ClojurePluginBootstrap")
      (.getDeclaredConstructor (into-array Class []))
      (.newInstance (into-array Object []))))

(deftest the-entry-point-is-java-not-clojure
  (testing "loading a gen-class artifact is what triggers Clojure's runtime,
            so the class that fixes the classloader cannot itself be one"
    (let [c (Class/forName "hbt.sonar.ClojurePluginBootstrap")]
      (is (contains? (set (.getInterfaces c)) Plugin))
      (is (not-any? #(= "clojure.lang.IType" (.getName ^Class %)) (.getInterfaces c))
          "a Clojure deftype would defeat the purpose"))))

(deftest it-delegates-to-the-clojure-plugin
  (let [ctx (Plugin$Context. (runtime))]
    (.define (bootstrap) ctx)
    (testing "every extension the Clojure side registers arrives"
      (is (= 11 (count (filter class? (.getExtensions ctx))))))))

(deftest it-restores-the-context-classloader
  (let [ctx    (Plugin$Context. (runtime))
        marker (java.net.URLClassLoader. (into-array java.net.URL []))
        thread (Thread/currentThread)
        before (.getContextClassLoader thread)]
    (try
      (.setContextClassLoader thread marker)
      (.define (bootstrap) ctx)
      (testing "leaving it swapped would hand later extensions a loader that
                is not theirs"
        (is (identical? marker (.getContextClassLoader thread))))
      (finally
        (.setContextClassLoader thread before)))))
