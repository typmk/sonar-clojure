(ns hbt.sonar.gen
  "Build-time: derive the Sonar rule catalogue from clj-kondo's own default
  config. Run under the :gen-rules alias, never at runtime.

  Emits Sonar enum *names*. The catalogue previously carried its own
  keywords, which `hbt.sonar.rules` then translated back through four
  parallel maps -- so adding a quality meant editing two files and nothing
  connected them. Naming the enums here removes the translation."
  (:require [clojure.data.json :as json]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.pprint :as pp]))

(defn clj-kondo-version
  "Read from deps.edn rather than from the loaded library, so the recorded
  version is the one this repository declares. clj-kondo exposes no version
  var; its jar name is the only other witness and that is not on the runtime
  classpath at all."
  []
  (get-in (edn/read-string (slurp "deps.edn"))
          [:aliases :gen-rules :extra-deps 'clj-kondo/clj-kondo :mvn/version]))

(def ^:private quality
  "clj-kondo linter -> the software quality it actually bears on.
  Anything unlisted is a maintainability concern."
  {:unresolved-symbol      "RELIABILITY"
   :unresolved-var         "RELIABILITY"
   :unresolved-namespace   "RELIABILITY"
   :invalid-arity          "RELIABILITY"
   :type-mismatch          "RELIABILITY"
   :not-a-function         "RELIABILITY"
   :duplicate-map-key      "RELIABILITY"
   :duplicate-set-key      "RELIABILITY"
   :redefined-var          "RELIABILITY"
   :missing-test-assertion "RELIABILITY"
   :condition-always-true  "RELIABILITY"
   :syntax                 "RELIABILITY"
   :insecure-url           "SECURITY"})

(def ^:private attribute
  {"RELIABILITY" "LOGICAL" "SECURITY" "TRUSTWORTHY" "MAINTAINABILITY" "CLEAR"})

(def ^:private rule-type
  {"RELIABILITY" "BUG" "SECURITY" "VULNERABILITY" "MAINTAINABILITY" "CODE_SMELL"})

(defn- severity
  "clj-kondo level -> Sonar impact severity."
  [level]
  (case level :error "HIGH" :warning "MEDIUM" :info "LOW" "MEDIUM"))

(defn- rule [[k {:keys [level]}]]
  (let [q (get quality k "MAINTAINABILITY")]
    {:key       (name k)
     :name      (.replace (name k) \- \space)
     :level     (or level :warning)
     :quality   q
     :attribute (attribute q)
     :type      (rule-type q)
     :severity  (severity level)
     :url       (str "https://github.com/clj-kondo/clj-kondo/blob/master/doc/linters.md#" (name k))}))

(defn write-linters!
  "Emit resources/hbt/sonar/linters.edn from clj-kondo's default config."
  [_]
  (require 'clj-kondo.impl.config)
  (let [default @(resolve 'clj-kondo.impl.config/default-config)
        rules   (->> (:linters default) (map rule) (sort-by :key) vec)
        out     (io/file "resources" "hbt" "sonar" "linters.edn")]
    (io/make-parents out)
    (with-open [w (io/writer out)]
      (pp/pprint rules w))
    (println "wrote" (count rules) "rules ->" (str out))
    ;; The manifest is the rule registry: every metadata resource that ships.
    (let [dir (io/file "resources" "org" "sonar" "l10n" "clj" "rules" "clj-kondo")
          keys (->> (file-seq dir)
                    (map #(.getName ^java.io.File %))
                    (filter #(str/ends-with? % ".json"))
                    (map #(subs % 0 (- (count %) 5)))
                    sort vec)
          idx (io/file dir "index.edn")]
      (spit idx (pr-str keys))
      (println "wrote" (count keys) "rule keys ->" (str idx)))
    ;; Provenance. Which clj-kondo produced this catalogue is a fact about the
    ;; artifact, and until it was written down it lived in a commit message --
    ;; rank 4, and unable to fail a build. Recorded here, a test can assert it
    ;; against the declared dependency, so upgrading clj-kondo without
    ;; regenerating stops being a silent divergence.
    (let [out (io/file "resources" "hbt" "sonar" "provenance.edn")
          cwe (json/read-str (slurp (io/file "resources" "hbt" "sonar" "cwe.json")))]
      (spit out (pr-str {:rule-catalogue
                         {:source "clj-kondo default config"
                          :generated-by 'hbt.sonar.gen/generate
                          :clj-kondo-version (clj-kondo-version)
                          :rules (count rules)}
                         :cwe-catalogue
                         {:source (get cwe "source")
                          :catalogue (get cwe "catalogue")
                          :version (get cwe "version")
                          :date (get cwe "date")
                          :weaknesses (count (get cwe "weaknesses"))}}))
      (println "wrote provenance ->" (str out)))))
