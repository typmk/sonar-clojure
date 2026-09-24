(ns au.com.heisenbergtech.sonar.prose-sensor-test
  "A prose finding arrives in Sonar as an issue.

  `rules-declared-test` proves the key is registered and `sift`'s own suite
  proves the rule fires; neither proves the issue survives `save-security!`.
  It did not: every prose finding carried a keyword rule, `RuleKey/of` threw,
  the catch printed a line nobody gated, and the scanner saw nothing.
  Measured 2026-08-31. This runs the sensor against SonarSource's in-memory
  context, which is the only place that failure is visible."
  (:require [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing]])
  (:import [java.nio.charset StandardCharsets]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]
           [org.sonar.api.batch.fs InputFile$Type]
           [org.sonar.api.batch.fs.internal TestInputFileBuilder]
           [org.sonar.api.batch.sensor.internal SensorContextTester]
           [au.com.heisenbergtech.sonar ClojureSourceSensor]))

(defn- temp-dir ^java.io.File []
  (.toFile (Files/createTempDirectory "prose-sensor" (into-array FileAttribute []))))

(def ^:private src
  "(ns a)\n\n(defn merge-rows\n  \"This function is used for combining.\"\n  [left right]\n  [left right])\n")

(def ^:private analysis
  (str "{\"analysis\":{\"var-definitions\":["
       "{\"filename\":\"src/a.clj\",\"ns\":\"a\",\"name\":\"merge-rows\","
       "\"row\":3,\"col\":1,\"name-row\":3,\"name-col\":7,\"name-end-row\":3,\"name-end-col\":17,"
       "\"doc\":\"This function is used for combining.\",\"arglist-strs\":[\"[left right]\"]}],"
       "\"namespace-definitions\":[{\"filename\":\"src/a.clj\",\"name\":\"a\",\"row\":1,\"col\":1}]}}"))

(deftest a-hedged-docstring-arrives-as-an-issue
  (let [base (temp-dir)]
    (spit (doto (io/file base "src/a.clj") io/make-parents) src)
    (spit (doto (io/file base "target/clj-kondo-analysis.json") io/make-parents) analysis)
    (let [ctx (SensorContextTester/create base)
          f   (-> (TestInputFileBuilder. "mod" "src/a.clj")
                  (.setModuleBaseDir (.toPath base))
                  (.setLanguage "clj")
                  (.setType InputFile$Type/MAIN)
                  (.setCharset StandardCharsets/UTF_8)
                  (.setContents src)
                  (.build))]
      (.add (.fileSystem ctx) f)
      (.execute (ClojureSourceSensor.) ctx)
      (let [rules (set (map #(.rule (.ruleKey %)) (.allIssues ctx)))]
        (testing "the hedge and the unnamed parameters each land under the key the catalogue registered"
          (is (contains? rules "doc-hedge") (str "issues saved: " rules))
          (is (contains? rules "doc-params-unnamed") (str "issues saved: " rules)))
        (testing "a namespace without a docstring is not an issue: sift turns ns-missing off by default"
          (is (not (contains? rules "doc-ns-missing")) (str "issues saved: " rules)))))))
