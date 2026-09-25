(ns build
  (:require [net.typemark.sonar.provenance :as provenance]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.tools.build.api :as b])
  (:import [java.security MessageDigest]))

(defn- description
  "Folded into the plugin description so the catalogue versions show on
  SonarQube's Marketplace page. Built by the plugin's own provenance code, so
  the jar cannot describe itself differently from how it reports itself."
  []
  (str "Indexes Clojure sources and imports clj-kondo findings. "
       (provenance/summary) "."))

(def plugin-key "clojure")

(def version
  "The single source of the plugin's version. A release is this string plus a
  matching `v`-prefixed annotated tag on a clean tree; `release` enforces both
  rather than trusting that whoever built it remembered."
  "0.1.4")

(defn- git [& args]
  (str/trim (or (b/git-process {:git-args (str/join " " args)}) "")))

(defn- revision []
  (let [sha   (git "rev-parse" "HEAD")
        dirty (seq (git "status" "--porcelain"))]
    {:sha sha :dirty? (boolean dirty)}))

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
                  ;; Only namespaces that exist here. Fifteen that moved to sift on
                  ;; 2026-08-13 (forms, tree, security, …) were still listed and the
                  ;; compile failed on the first of them from that day until 2026-08-31;
                  ;; the suite kept passing against a stale target/classes.
                  :ns-compile '[net.typemark.sonar.const
                                net.typemark.sonar.inputs
                                net.typemark.sonar.report
                                net.typemark.sonar.classpath
                                net.typemark.sonar.metadata
                                net.typemark.sonar.hooks
                                net.typemark.sonar.codecov
                                net.typemark.sonar.external
                                net.typemark.sonar.external-rules
                                net.typemark.sonar.external-sensor
                                net.typemark.sonar.junit
                                net.typemark.sonar.test-sensor
                                net.typemark.sonar.language
                                net.typemark.sonar.rules
                                net.typemark.sonar.profile
                                net.typemark.sonar.sensor
                                net.typemark.sonar.lcov
                                net.typemark.sonar.coverage-sensor
                                net.typemark.sonar.source-sensor
                                net.typemark.sonar.provenance
                                net.typemark.sonar.cwe
                                net.typemark.sonar.metrics-def
                                net.typemark.sonar.completeness-sensor
                                net.typemark.sonar.plugin]}))

(defn- sha256
  "The checksum published beside the jar. SonarQube does not verify plugin
  signatures for a plugin dropped into extensions/plugins, so integrity at
  deploy time is whatever the operator can check by hand -- which means it has
  to be published, not merely computable."
  [^String path]
  (let [d (MessageDigest/getInstance "SHA-256")
        buf (byte-array 65536)]
    (with-open [in (io/input-stream path)]
      (loop []
        (let [n (.read in buf)]
          (when (pos? n) (.update d buf 0 n) (recur)))))
    (apply str (map #(format "%02x" %) (.digest d)))))

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
                       "Implementation-Version"  (let [{:keys [sha dirty?]} (revision)]
                                                   (str version "+" sha (when dirty? ".dirty")))
                       "Build-Revision"          (:sha (revision))
                       "Build-Status"            (if (:dirty? (revision)) "dirty" "clean")
                       "Plugin-Class"            "net.typemark.sonar.ClojurePluginBootstrap"
                       "Plugin-Description"      (description)
                       "Plugin-License"          "EPL-2.0"
                       "Plugin-OrganizationName" "Typemark"
                       "Plugin-Homepage"         "https://github.com/typmk/sonar-clojure"
                       "Plugin-SourcesUrl"       "https://github.com/typmk/sonar-clojure"
                       ;; Compared against the PLUGIN API version, not the
                       ;; SonarQube version. 10.13 is where
                       ;; PropertyDefinition$ConfigScope first appears, which
                       ;; plugin.clj uses -- measured across the published
                       ;; artifacts, 10.12 lacks it and 10.13 has it.
                       ;; Declaring 10.0 did not make the plugin work on 10.7;
                       ;; it made SonarQube accept a plugin that then died with
                       ;; ClassNotFoundException and took the server down.
                       "Sonar-Version"           "10.13"
                       "Plugin-RequiredForLanguages" "clj"}})
  (let [sum (sha256 jar-file)
        {:keys [sha dirty?]} (revision)]
    (spit (str jar-file ".sha256") (str sum "  " (.getName (io/file jar-file)) "\n"))
    (println "built" jar-file)
    (println "  version " version "+" sha (if dirty? "(DIRTY TREE)" ""))
    (println "  sha256  " sum)))

(defn release
  "A build whose version means something.

  `uber` will happily produce a jar from uncommitted work, which is right for
  iterating and wrong for anything handed to someone else -- the version in the
  manifest then names a commit that does not contain the code in the jar. This
  refuses that: clean tree, and an annotated tag matching the version, before
  it builds. Then it signs, if a key is configured.

  Signing is GPG detached, not jarsigner: SonarQube does not check plugin
  signatures, so the value is authenticity for whoever installs it, and a
  detached .asc is verifiable without unpacking the jar. Set
  SONAR_CLOJURE_GPG_KEY to the key id. No key, no signature, and it says so --
  it does not quietly produce an unsigned release that looks signed."
  [_]
  (let [{:keys [sha dirty?]} (revision)
        tag (str "v" version)
        tagged (git "tag" "--points-at" "HEAD")]
    (when dirty?
      (throw (ex-info (str "release refuses a dirty tree: the manifest would name " sha
                           ", which does not contain the working changes")
                      {:sha sha})))
    (when-not (contains? (set (str/split-lines tagged)) tag)
      (throw (ex-info (str "release requires HEAD to carry the tag " tag
                           " -- create it with: git tag -a " tag " -m '" tag "'")
                      {:sha sha :tags tagged :expected tag})))
    (uber nil)
    (if-let [key-id (System/getenv "SONAR_CLOJURE_GPG_KEY")]
      (do (b/process {:command-args ["gpg" "--batch" "--yes" "--local-user" key-id
                                     "--armor" "--detach-sign" jar-file]})
          (println "  signed  " (str jar-file ".asc") "with" key-id))
      (println "  UNSIGNED: set SONAR_CLOJURE_GPG_KEY to a gpg key id to sign this release"))
    (println "  released" tag "at" sha)))
