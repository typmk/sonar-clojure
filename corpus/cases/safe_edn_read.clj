(ns corpus.safe-edn-read (:require [clojure.edn :as edn]))
(defn parse [req] (edn/read-string (get-in req [:params :expr])))
