(ns corpus.safe-datomic-param (:require [datomic.api :as d]))
(defn search [req db]
  (d/q '[:find ?e :in $ ?n :where [?e :p/n ?n]] db (get-in req [:params :n])))
