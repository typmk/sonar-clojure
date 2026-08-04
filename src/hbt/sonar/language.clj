(ns hbt.sonar.language
  "Claims .clj/.cljs/.cljc/.edn so Sonar INDEXES them. Without an indexed
  file there is nothing to hang an issue on, and imported findings are
  discarded without a message."
  (:require [clojure.string :as str]
            [hbt.sonar.const :as const])
  (:gen-class
   :name hbt.sonar.ClojureLanguage
   :implements [org.sonar.api.resources.Language]
   ;; A typed constructor. deftype erases reference hints to Object and the
   ;; container then cannot resolve the parameter -- gen-class is the only
   ;; form that emits the real signature.
   :constructors {[org.sonar.api.config.Configuration] []}
   :init init
   :state state))

(defn -init [config]
  [[] {:config config}])

(defn -getKey [_] const/language-key)
(defn -getName [_] const/language-name)

(defn -getFileSuffixes [this]
  (let [^org.sonar.api.config.Configuration cfg (:config (.state this))
        configured (seq (remove str/blank?
                                (.getStringArray cfg const/suffixes-prop)))]
    (into-array String (or configured const/default-suffixes))))

(defn -publishAllFiles [_] true)
(defn -filenamePatterns [_] (into-array String []))
