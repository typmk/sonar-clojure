(ns corpus.datomic-query-built (:require [datomic.api :as d]))
(defn search [req db]
  (d/q (read-string (str "[:find ?e :where [?e :p/n \"" (get-in req [:params :n]) "\"]]")) db))
