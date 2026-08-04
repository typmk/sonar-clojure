(ns build
  (:require [clojure.tools.build.api :as b]))

(def plugin-key "clojure")
(def version "0.1.0")
(def class-dir "target/classes")
(def jar-file (format "target/sonar-clojure-plugin-%s.jar" version))

(def api-excludes ["^org/sonar/api/.*" "^org/sonar/plugins/.*"])

(defn- basis [] (b/create-basis {:aliases [:provided]}))

(defn javac*
  "The bootstrap entry point is Java because loading a gen-class artifact is
  what triggers Clojure's runtime -- the classloader has to be corrected by
  something that carries no Clojure static initialiser."
  [_]
  (b/javac {:src-dirs  ["java"]
            :class-dir class-dir
            :basis     (basis)
            :javac-opts ["--release" "17"]}))

(defn clean [_] (b/delete {:path "target"}) (b/delete {:path "classes"}))

(defn compile-clj* [_]
  (b/copy-dir {:src-dirs ["resources"] :target-dir class-dir})
  (b/compile-clj {:basis      (basis)
                  :src-dirs   ["src"]
                  :class-dir  class-dir
                  :ns-compile '[hbt.sonar.const
                                hbt.sonar.forms
                                hbt.sonar.report
                                hbt.sonar.tree
                                hbt.sonar.classpath
                                hbt.sonar.metadata
                                hbt.sonar.security
                                hbt.sonar.interop
                                hbt.sonar.concurrency
                                hbt.sonar.dictionary
                                hbt.sonar.regex
                                hbt.sonar.tests
                                hbt.sonar.web
                                hbt.sonar.access
                                hbt.sonar.hooks
                                hbt.sonar.codecov
                                hbt.sonar.callgraph
                                hbt.sonar.external
                                hbt.sonar.external-rules
                                hbt.sonar.external-sensor
                                hbt.sonar.junit
                                hbt.sonar.test-sensor
                                hbt.sonar.language
                                hbt.sonar.rules
                                hbt.sonar.profile
                                hbt.sonar.sensor
                                hbt.sonar.parse
                                hbt.sonar.metrics
                                hbt.sonar.highlight
                                hbt.sonar.analysis
                                hbt.sonar.lcov
                                hbt.sonar.coverage-sensor
                                hbt.sonar.source-sensor
                                hbt.sonar.plugin]}))

(defn uber [_]
  (clean nil)
  (b/copy-file {:src "LICENSE" :target (str class-dir "/META-INF/LICENSE")})
  (b/copy-file {:src "NOTICE" :target (str class-dir "/META-INF/NOTICE")})
  (javac* nil)
  (compile-clj* nil)
  (b/uber {:class-dir class-dir
           :uber-file jar-file
           :basis     (basis)
           :exclude   api-excludes
           :manifest  {"Plugin-Key"              plugin-key
                       "Plugin-Name"             "Clojure (clj-kondo)"
                       "Plugin-Version"          version
                       "Plugin-Class"            "hbt.sonar.ClojurePluginBootstrap"
                       "Plugin-Description"      "Indexes Clojure sources and imports clj-kondo findings."
                       "Plugin-License"          "EPL-2.0"
                       "Plugin-OrganizationName" "Heisenberg Technologies"
                       "Plugin-Homepage"         "https://hbtcomputers.com.au"
                       "Plugin-SourcesUrl"       "https://github.com/hbtweb"
                       "Sonar-Version"           "10.0"
                       "Plugin-RequiredForLanguages" "clj"}})
  (println "built" jar-file))
