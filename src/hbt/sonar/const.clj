(ns hbt.sonar.const)

(def language-key "clj")
(def language-name "Clojure")
(def repository-key "clj-kondo")
(def profile-name "Sane")

(def suffixes-prop "sonar.clj.file.suffixes")
(def patterns-prop "sonar.clj.file.patterns")
(def report-paths-prop "sonar.clojure.kondo.reportPaths")
(def analysis-paths-prop "sonar.clojure.kondo.analysisPaths")
(def coverage-paths-prop "sonar.clojure.cloverage.reportPaths")
(def test-report-paths-prop "sonar.clojure.kaocha.reportPaths")

(def default-suffixes [".clj" ".cljs" ".cljc" ".edn" ".bb"])
(def default-report "target/clj-kondo.json")
(def default-analysis "target/clj-kondo-analysis.json")
(def default-coverage "target/coverage/codecov.json")
(def default-test-report "target/junit.xml")

(def external-report-props
  {"splint"     "sonar.clojure.splint.reportPaths"
   "clj-holmes" "sonar.clojure.cljholmes.reportPaths"
   "eastwood"   "sonar.clojure.eastwood.reportPaths"
   "nvd"        "sonar.clojure.nvd.reportPaths"})

(def unknown-rule "unknown-linter")
