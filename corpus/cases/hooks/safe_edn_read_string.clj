(ns corpus.hooks.safe-edn-read-string (:require [clojure.edn :as edn]))
(defn parse [s] (edn/read-string s))
