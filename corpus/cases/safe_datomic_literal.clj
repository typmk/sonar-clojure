(ns corpus.safe-datomic-literal (:require [datomic.api :as d]))
(defn all [db] (d/q '[:find ?e :where [?e :p/sku _]] db))
