(ns net.typemark.sonar.prepare
  "The reports the plugin reads, written where it looks for them, in one
  command. The plugin invokes nothing inside the scanner; this runs before it,
  in the project, as a tool:

    clojure -Ttools install-latest :lib io.github.typmk/sonar-clojure :as sonar-clojure
    clojure -Tsonar-clojure prepare

  It installs the security hooks where clj-kondo loads them, lints once for
  findings and analysis together, and says which of the plugin's inputs are
  still missing and how to produce each. Coverage and test results stay the
  project's own: they come from its test runner, which this cannot choose.

  clj-kondo is the binary on PATH, not a dependency: the plugin jar is built
  from this repository's :deps, and clj-kondo inside it would be dead weight
  on every SonarQube server."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [net.typemark.sonar.inputs :as inputs])
  (:import [java.io File]
           [java.net URI]
           [java.nio.file CopyOption FileSystems Files LinkOption Path StandardCopyOption]
           [java.nio.file.attribute FileAttribute]))

(set! *warn-on-reflection* true)

(def hooks-resource
  "The export directory, in clj-kondo's layout: `<group>/<artifact>` under
  `clj-kondo.exports`, installed to `.clj-kondo/imports/<group>/<artifact>`."
  "clj-kondo.exports/net.typemark/sonar-clojure")

(def analysis-config
  "{:output {:format :json} :analysis {:locals true :keywords true}}")

(defn- copy-tree!
  "Copies every file under `from` to the same relative path under `to`."
  [^Path from ^Path to]
  (with-open [s (Files/walk from (make-array java.nio.file.FileVisitOption 0))]
    (doseq [^Path p (iterator-seq (.iterator s))
            :when (Files/isRegularFile p (make-array LinkOption 0))]
      (let [dest (.resolve to (str (.relativize from p)))]
        (Files/createDirectories (.getParent dest) (make-array FileAttribute 0))
        (Files/copy p dest ^"[Ljava.nio.file.CopyOption;"
                    (into-array CopyOption [StandardCopyOption/REPLACE_EXISTING]))))))

(defn install-hooks!
  "Copies the hooks from the classpath into `dir`'s `.clj-kondo/imports`,
  where clj-kondo loads them with no `:config-paths`. Replaces an older copy:
  the hooks are this plugin's, and a stale one reports against rules the
  plugin has since changed. Returns the directory written."
  [^File dir]
  (let [url (or (io/resource hooks-resource)
                (throw (ex-info (str hooks-resource " is not on the classpath") {})))
        dest (.toPath (io/file dir ".clj-kondo" "imports" "net.typemark" "sonar-clojure"))
        uri (.toURI url)]
    (if (= "jar" (.getScheme uri))
      (let [[jar entry] (str/split (str uri) #"!" 2)]
        (with-open [fs (FileSystems/newFileSystem (URI. jar) {})]
          (copy-tree! (.getPath fs entry (make-array String 0)) dest)))
      (copy-tree! (.toPath (io/file uri)) dest))
    (.toFile dest)))

(defn lint!
  "Runs clj-kondo over `paths` in `dir`, writing findings and analysis to
  `out`. clj-kondo exits 2 on warnings and 3 on errors, which are findings,
  not failures; anything else is."
  [^File dir paths ^File out]
  (io/make-parents out)
  (let [cmd (into ["clj-kondo" "--lint"] (concat paths ["--config" analysis-config]))
        p (try
            (-> (ProcessBuilder. ^java.util.List cmd)
                (.directory dir)
                (.redirectOutput out)
                (.redirectError java.lang.ProcessBuilder$Redirect/INHERIT)
                (.start))
            (catch java.io.IOException e
              (throw (ex-info (str "clj-kondo is not on PATH. Install it: "
                                   "https://github.com/clj-kondo/clj-kondo/blob/master/doc/install.md")
                              {:cmd cmd} e))))
        code (.waitFor p)]
    (when-not (#{0 2 3} code)
      (throw (ex-info (str "clj-kondo exited " code) {:cmd cmd :exit code})))
    out))

(defn- missing-inputs
  "The plugin's inputs not on disk under `dir`, at their default paths."
  [^File dir]
  (for [{:keys [default] :as in} inputs/inputs
        :let [f (io/file dir default)]
        :when (not (.isFile f))]
    in))

(defn prepare
  "Install the hooks, lint once, and report what the plugin will still miss.

  Options:
    :dir  the project root (default \".\")
    :lint the paths to lint (default whichever of src, test exist)"
  [{:keys [dir lint] :or {dir "."}}]
  (let [dir (.getCanonicalFile (io/file (str dir)))
        paths (or (seq (map str lint))
                  (seq (filter #(.isDirectory (io/file dir %)) ["src" "test"]))
                  (throw (ex-info "nothing to lint: no src or test, and no :lint given" {:dir (str dir)})))
        hooks (install-hooks! dir)
        out (lint! dir paths (io/file dir (:default (inputs/input :kondo))))]
    (println "hooks    " (str (.relativize (.toPath dir) (.toPath hooks))))
    (println "clj-kondo" (str (.relativize (.toPath dir) (.toPath out))) "-- findings and analysis," (str/join " " paths))
    (doseq [{:keys [label costs doc]} (missing-inputs dir)]
      (println)
      (println "missing  " label "--" costs)
      (println "         " doc))
    nil))
