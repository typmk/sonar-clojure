(ns au.com.heisenbergtech.sonar.language
  "Claims .clj/.cljs/.cljc/.edn/.bb so Sonar INDEXES them. Without an indexed
  file there is nothing to hang an issue on, and imported findings are
  discarded without a message."
  (:require [clojure.string :as str]
            [au.com.heisenbergtech.sonar.const :as const])
  (:gen-class
   :name au.com.heisenbergtech.sonar.ClojureLanguage
   :implements [org.sonar.api.resources.Language]
   :constructors {[org.sonar.api.config.Configuration] []}
   :init init
   :state state))

(set! *warn-on-reflection* true)

(defn -init [config]
  [[] {:config config}])

(defn -getKey [_] const/language-key)
(defn -getName [_] const/language-name)

(defn- suffixes [this]
  (let [^org.sonar.api.config.Configuration cfg (:config (.state this))
        configured (seq (remove str/blank?
                                (.getStringArray cfg const/suffixes-prop)))]
    (or configured const/default-suffixes)))

(defn -getFileSuffixes [this]
  (into-array String (suffixes this)))

(defn -publishAllFiles [_] true)

(defn -filenamePatterns
  "Derived from the suffixes, NOT stubbed empty.

  This is the method the scanner actually reads: it logs `Declared patterns
  of language Clojure were converted to sonar.lang.patterns.clj` and, when
  the array is empty, claims nothing. Measured against SonarQube 26.7 --
  36 files preprocessed, `0 languages detected`, every sensor skipped, and
  no error anywhere to say why.

  The interface supplies a default that derives these from the suffixes, but
  gen-class emits a stub for every interface method including defaults, so
  the default is unreachable and this has to do the work itself."
  [this]
  (into-array String (map #(str "**/*" %) (suffixes this))))
