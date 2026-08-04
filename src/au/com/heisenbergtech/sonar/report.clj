(ns au.com.heisenbergtech.sonar.report
  "Locating a report on disk, and matching a path inside it to a file Sonar
  indexed.

  Both sensors and the symbol loader had their own copy of this. It is the
  code path where a mistake means findings silently disappear between the
  linter and the dashboard, so it exists once.

  `inputs` is the same argument applied to WHICH reports get read. Each of the
  four was previously named in four places -- the property definition, the
  sensor, the completeness check and a test -- with the property key and the
  default paired by hand every time. A mispairing reads the wrong file and
  reports nothing, and the four copies had already drifted: the cloverage
  property told the SonarQube UI to use `--lcov`, the format this plugin
  warns against. One table, and everything else derives from it."
  (:require [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [java.io File]))

(def inputs
  "Every report this plugin reads. Ordered by how misleading its silence is."
  [{:id :kondo
    :prop "sonar.clojure.kondo.reportPaths"
    :default "target/clj-kondo.json"
    :name "clj-kondo report paths"
    :label "clj-kondo findings"
    :costs "no rule findings at all -- the project reads as having zero issues"
    :doc (str "Paths to clj-kondo JSON reports, relative to the module base. "
              "Produce one with: clj-kondo --lint src test "
              "--config '{:output {:format :json}}' > target/clj-kondo.json")}

   {:id :coverage
    :prop "sonar.clojure.cloverage.reportPaths"
    :default "target/coverage/codecov.json"
    :name "cloverage report paths"
    :label "cloverage coverage"
    :costs "coverage reports as 0%, failing the quality gate for a reason unrelated to the tests"
    :doc (str "Paths to cloverage reports. Use --codecov, not --lcov: cloverage's "
              "lcov writer records a partially covered line as fully covered. "
              "Produce one with: clojure -M:coverage -m cloverage.coverage "
              "--codecov -p src -s test")}

   {:id :analysis
    :prop "sonar.clojure.kondo.analysisPaths"
    :default "target/clj-kondo-analysis.json"
    :name "clj-kondo analysis paths"
    :label "clj-kondo analysis"
    :costs "no symbol navigation, no dictionary check, no interprocedural taint"
    :doc (str "Paths to clj-kondo analysis JSON, which drives symbol navigation. "
              "Produce one with: clj-kondo --lint src test --config "
              "'{:output {:format :json :analysis {:locals true :keywords true}}}' "
              "> target/clj-kondo-analysis.json")}

   {:id :tests
    :prop "sonar.clojure.kaocha.reportPaths"
    :default "target/junit.xml"
    :name "kaocha JUnit report paths"
    :label "kaocha test execution"
    :costs "no test counts; coverage is the only evidence the code is exercised"
    :doc (str "Paths to kaocha's JUnit XML. Produce one by adding the "
              "kaocha-junit-xml plugin and running: "
              "bin/kaocha --plugin kaocha.plugin/junit-xml "
              "--junit-xml-file target/junit.xml")}])

(def input
  "Report id -> its entry. Throws on an unknown id rather than resolving to
  nil, which would silently read no paths at all."
  (let [m (into {} (map (juxt :id identity)) inputs)]
    (fn [id]
      (or (get m id)
          (throw (ex-info (str "sonar-clojure: no such report input: " id)
                          {:id id :known (mapv :id inputs)}))))))

(defn paths
  "The configured report paths for `prop`, or `default` when unset, each
  resolved against the module base unless already absolute."
  [ctx prop default]
  (let [base  (.baseDir (.fileSystem ctx))
        given (remove str/blank? (.getStringArray (.config ctx) prop))]
    (for [p (if (seq given) given (if default [default] []))]
      (let [f (io/file p)]
        (if (.isAbsolute f) f (io/file base p))))))

(defn for-input
  "The paths configured for a registered report, by id. Preferred over `paths`:
  it makes the property and its default impossible to mispair."
  [ctx id]
  (let [{:keys [prop default]} (input id)]
    (paths ctx prop default)))

(defn exists? [^File f] (.isFile f))

(defn present?
  "Whether a registered report is on disk, at a configured or default path."
  [ctx id]
  (boolean (some exists? (for-input ctx id))))

(defn input-file
  "The InputFile for a path named inside a report, or nil.

  Three attempts, because the tools disagree about what a path is relative
  to. cloverage's lcov writes `src/au/com/heisenbergtech/sonar/x.clj` while its codecov writer
  drops the source root and writes `au/com/heisenbergtech/sonar/x.clj`; clj-kondo writes
  whatever its working directory made it. A path that fails to resolve costs
  the finding silently, so it is worth trying all three.

  The suffix match is last and requires a path separator boundary, so
  `a/foo.clj` cannot match `b/megafoo.clj`."
  [ctx ^String filename]
  (let [fs  (.fileSystem ctx)
        ps  (.predicates fs)
        abs (.getAbsolutePath (io/file (.baseDir fs) filename))]
    (or (.inputFile fs (.hasPath ps filename))
        (.inputFile fs (.hasAbsolutePath ps abs))
        (let [needle (str "/" filename)]
          (->> (.inputFiles fs (.all ps))
               (filter #(str/ends-with? (str (.path ^org.sonar.api.batch.fs.InputFile %)) needle))
               first)))))
