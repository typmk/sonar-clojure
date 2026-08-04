(ns hbt.sonar.gen
  "Build-time: derive the Sonar rule catalogue from clj-kondo's own default
  config. Run under the :gen-rules alias, never at runtime.

  Emits Sonar enum *names*. The catalogue previously carried its own
  keywords, which `hbt.sonar.rules` then translated back through four
  parallel maps -- so adding a quality meant editing two files and nothing
  connected them. Naming the enums here removes the translation."
  (:require [clojure.java.io :as io]
            [clojure.pprint :as pp]))

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
     ;; clj-kondo's own docs are the description; linking beats paraphrasing,
     ;; because a paraphrase here is a copy that rots.
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
    (println "wrote" (count rules) "rules ->" (str out))))
