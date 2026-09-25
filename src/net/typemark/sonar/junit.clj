(ns net.typemark.sonar.junit
  "Reads the JUnit XML kaocha emits with the kaocha-junit-xml plugin.

  Sonar's own generic test-execution format is a different XML again, so
  reading JUnit directly saves a conversion step and a second thing to keep
  in step -- kaocha already writes this file for CI."
  (:require [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [javax.xml.parsers DocumentBuilderFactory]
           [org.w3c.dom Element Node]))

(set! *warn-on-reflection* true)

(defn- safe-factory
  "External entity resolution off. This parser reads a file produced by CI,
  and a report is exactly the kind of input an attacker reaches first."
  ^DocumentBuilderFactory []
  (doto (DocumentBuilderFactory/newInstance)
    (.setFeature "http://apache.org/xml/features/disallow-doctype-decl" true)
    (.setFeature "http://xml.org/sax/features/external-general-entities" false)
    (.setFeature "http://xml.org/sax/features/external-parameter-entities" false)
    (.setXIncludeAware false)
    (.setExpandEntityReferences false)))

(defn- elements [^Node node tag]
  (let [nl (.getElementsByTagName ^Element node tag)]
    (for [i (range (.getLength nl))] (.item nl i))))

(defn- attr [^Element e k] (let [v (.getAttribute e k)] (when-not (str/blank? v) v)))

(defn- child-count [^Element e tag] (count (elements e tag)))

(defn- seconds->ms [s]
  (when s (try (long (* 1000 (Double/parseDouble s))) (catch Exception _ nil))))

(defn ns->path
  "A Clojure namespace to the source path it almost certainly lives at:
  dots become slashes, hyphens become underscores. Returned without an
  extension so the caller can try each dialect."
  [namespace-name]
  (-> namespace-name
      (str/replace "." "/")
      (str/replace "-" "_")))

(defn parse
  "JUnit XML -> {namespace {:tests n :failures n :errors n :skipped n :duration-ms n}}.

  Aggregated per namespace rather than per testcase, because Sonar's test
  metrics are per file and a Clojure test namespace is a file."
  [xml-text]
  (when-not (str/blank? xml-text)
    (let [doc (.parse (.newDocumentBuilder (safe-factory))
                      (io/input-stream (.getBytes ^String xml-text "UTF-8")))]
      (reduce
       (fn [acc ^Element suite]
         (let [cases (elements suite "testcase")]
           (reduce
            (fn [a ^Element c]
              (let [nsname (or (attr c "classname") (attr suite "name"))]
                (if-not nsname
                  a
                  (update a nsname
                          (fnil (fn [m]
                                  (-> m
                                      (update :tests inc)
                                      (update :failures + (child-count c "failure"))
                                      (update :errors + (child-count c "error"))
                                      (update :skipped + (child-count c "skipped"))
                                      (update :duration-ms + (or (seconds->ms (attr c "time")) 0))))
                                {:tests 0 :failures 0 :errors 0 :skipped 0 :duration-ms 0})))))
            acc cases)))
       {}
       (elements (.getDocumentElement doc) "testsuite")))))

(defn totals [parsed]
  (reduce (fn [a [_ m]] (merge-with + a m))
          {:tests 0 :failures 0 :errors 0 :skipped 0 :duration-ms 0}
          parsed))
