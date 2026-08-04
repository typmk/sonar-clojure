(ns build
  (:require [clojure.tools.build.api :as b]))

(def plugin-key "clojure")
(def version "0.1.0")
(def class-dir "target/classes")
(def jar-file (format "target/sonar-clojure-plugin-%s.jar" version))

;; Sonar hands the plugin its own copy of the API. Bundling it produces two
;; class identities for every interface and every extension fails to register.
(def api-excludes ["^org/sonar/api/.*" "^org/sonar/plugins/.*"])

(defn- basis [] (b/create-basis {:aliases [:provided]}))

(defn clean [_] (b/delete {:path "target"}) (b/delete {:path "classes"}))

(defn compile-clj* [_]
  (b/copy-dir {:src-dirs ["resources"] :target-dir class-dir})
  (b/compile-clj {:basis      (basis)
                  :src-dirs   ["src"]
                  :class-dir  class-dir
                  :ns-compile '[hbt.sonar.const
                                hbt.sonar.forms
                                hbt.sonar.report
                                hbt.sonar.language
                                hbt.sonar.rules
                                hbt.sonar.profile
                                hbt.sonar.sensor
                                hbt.sonar.parse
                                hbt.sonar.metrics
                                hbt.sonar.highlight
                                hbt.sonar.analysis
                                hbt.sonar.lcov
                                hbt.sonar.source-sensor
                                hbt.sonar.coverage-sensor
                                hbt.sonar.plugin]}))

(defn uber [_]
  (clean nil)
  (compile-clj* nil)
  (b/uber {:class-dir class-dir
           :uber-file jar-file
           :basis     (basis)
           :exclude   api-excludes
           :manifest  {"Plugin-Key"              plugin-key
                       "Plugin-Name"             "Clojure (clj-kondo)"
                       "Plugin-Version"          version
                       "Plugin-Class"            "hbt.sonar.ClojurePlugin"
                       "Plugin-Description"      "Indexes Clojure sources and imports clj-kondo findings."
                       "Plugin-License"          "AGPL-3.0"
                       "Plugin-OrganizationName" "Heisenberg Technologies"
                       "Plugin-Homepage"         "https://hbtcomputers.com.au"
                       "Plugin-SourcesUrl"       "https://github.com/hbtweb"
                       ;; Floor, not a tested claim: verified only against
                       ;; SonarQube 26.7 with sonar-plugin-api 13.9.
                       "Sonar-Version"           "10.0"}})
  (println "built" jar-file))
