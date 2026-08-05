(ns corpus.tenancy.safe-compat-layer (:require [datomic.api :as d]))
(defn carries [db]
  (d/q '[:find ?a ?b :where [?a :std/carries ?b] [?a :conn/adapts ?b]] db))
