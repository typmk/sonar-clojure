(ns build
  (:require [clojure.edn :as edn]
            [clojure.tools.build.api :as b]))

(defn- provenance
  "The generation record, folded into the plugin description so the catalogue
  versions are visible in SonarQube's Marketplace page rather than only in a
  commit message."
  []
  (let [{:keys [rule-catalogue cwe-catalogue]}
        (edn/read-string (slurp "resources/hbt/sonar/provenance.edn"))]
    (str "Indexes Clojure sources and imports clj-kondo findings. "
         (:rules rule-catalogue) " rules generated from clj-kondo "
         (:clj-kondo-version rule-catalogue) "; CWE mappings validated against "
         (:catalogue cwe-catalogue) " v" (:version cwe-catalogue) ".")))

(def plugin-key "clojure")
(def version "0.1.0")
(def class-dir "target/classes")

(def stage-dir
  "Where the jar is assembled: compiled classes PLUS resources.

  Resources are deliberately NOT copied into class-dir. `target/classes` sits
  ahead of `resources` on the test classpath, so a copy there shadows the
  files on disk and the suite starts validating the last build instead of the
  current source -- measured: three CWE mappings edited in `resources` and the
  test still read the stale values. Staging separately means the shadow
  cannot exist."
  "target/stage")
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
                                hbt.sonar.provenance
                                hbt.sonar.cwe
                                hbt.sonar.metrics-def
                                hbt.sonar.completeness-sensor
                                hbt.sonar.plugin]}))

(defn uber [_]
  (clean nil)
  (javac* nil)
  (compile-clj* nil)
  (b/copy-dir {:src-dirs ["resources" class-dir] :target-dir stage-dir})
  (b/copy-file {:src "LICENSE" :target (str stage-dir "/META-INF/LICENSE")})
  (b/copy-file {:src "NOTICE" :target (str stage-dir "/META-INF/NOTICE")})
  (b/uber {:class-dir stage-dir
           :uber-file jar-file
           :basis     (basis)
           :exclude   api-excludes
           :manifest  {"Plugin-Key"              plugin-key
                       "Plugin-Name"             "Clojure (clj-kondo)"
                       "Plugin-Version"          version
                       "Plugin-Class"            "hbt.sonar.ClojurePluginBootstrap"
                       "Plugin-Description"      (provenance)
                       "Plugin-License"          "EPL-2.0"
                       "Plugin-OrganizationName" "Heisenberg Technologies"
                       "Plugin-Homepage"         "https://hbtcomputers.com.au"
                       "Plugin-SourcesUrl"       "https://github.com/hbtweb"
                       "Sonar-Version"           "10.0"
                       "Plugin-RequiredForLanguages" "clj"}})
  (println "built" jar-file))
