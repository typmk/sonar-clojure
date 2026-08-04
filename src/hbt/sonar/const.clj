(ns hbt.sonar.const)

(def language-key "clj")
(def language-name "Clojure")
(def repository-key "clj-kondo")
(def profile-name "Sane")

(def suffixes-prop "sonar.clojure.file.suffixes")
(def report-paths-prop "sonar.clojure.kondo.reportPaths")
(def analysis-paths-prop "sonar.clojure.kondo.analysisPaths")
(def coverage-paths-prop "sonar.clojure.cloverage.reportPaths")

(def default-suffixes [".clj" ".cljs" ".cljc" ".edn" ".bb"])
(def default-report "target/clj-kondo.json")
(def default-analysis "target/clj-kondo-analysis.json")
(def default-coverage "target/coverage/lcov.info")

;; A finding whose linter is absent from the generated catalogue lands here
;; rather than being dropped. A newer clj-kondo than the plugin was built
;; against must be visible, not silent.
(def unknown-rule "unknown-linter")
