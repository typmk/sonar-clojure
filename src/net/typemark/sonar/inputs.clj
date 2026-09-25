(ns net.typemark.sonar.inputs
  "Every report this plugin reads: its property, default path, and what its
  absence costs.

  Each of the four was previously named in four places -- the property
  definition, the sensor, the completeness check and a test -- with the
  property key and the default paired by hand every time. A mispairing reads
  the wrong file and reports nothing, and the four copies had already
  drifted: the cloverage property told the SonarQube UI to use `--lcov`, the
  format this plugin warns against. One table, and everything else derives
  from it.

  Plain data, loadable without the Sonar API, because `prepare` reads it
  outside a scanner.")

(def kondo-command
  "The one clj-kondo invocation both kondo inputs read. `:analysis` adds the
  analysis beside the findings in the same JSON document, so a second run
  would lint the same sources to write half of the same file."
  (str "clj-kondo --lint src test --config "
       "'{:output {:format :json} :analysis {:locals true :keywords true}}' "
       "> target/clj-kondo.json"))

(def inputs
  "Every report this plugin reads. Ordered by how misleading its silence is."
  [{:id :kondo
    :prop "sonar.clojure.kondo.reportPaths"
    :default "target/clj-kondo.json"
    :name "clj-kondo report paths"
    :label "clj-kondo findings"
    :costs "no rule findings at all -- the project reads as having zero issues"
    :doc (str "Paths to clj-kondo JSON reports, relative to the module base. "
              "One run writes the findings and the analysis together: "
              kondo-command)}

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
    :default "target/clj-kondo.json"
    :holds "\"analysis\":"
    :name "clj-kondo analysis paths"
    :label "clj-kondo analysis"
    :costs "no symbol navigation, no dictionary check, no interprocedural taint"
    :doc (str "Paths to clj-kondo analysis JSON, which drives symbol navigation. "
              "Unset, it is the findings report, which carries the analysis "
              "when produced with: " kondo-command)}

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
