(ns au.com.heisenbergtech.sonar.const)

(def language-key "clj")
(def language-name "Clojure")
(def repository-key "clj-kondo")
(def profile-name "Sane")

(def suffixes-prop "sonar.clj.file.suffixes")
(def patterns-prop "sonar.clj.file.patterns")

(def default-suffixes [".clj" ".cljs" ".cljc" ".edn" ".bb"])

(def external-report-props
  {"splint"     "sonar.clojure.splint.reportPaths"
   "clj-holmes" "sonar.clojure.cljholmes.reportPaths"
   "eastwood"   "sonar.clojure.eastwood.reportPaths"
   "nvd"        "sonar.clojure.nvd.reportPaths"
   "opengrep"   "sonar.clojure.opengrep.reportPaths"})

(def unknown-rule "unknown-linter")
