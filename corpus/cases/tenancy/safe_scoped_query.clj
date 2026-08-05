(ns corpus.tenancy.safe-scoped-query (:require [datomic.api :as d]))
(defn invoices-for [db owner]
  (d/q '[:find ?e :in $ ?owner :where [?e :document/type :invoice] [?e :obj/owner ?owner]] db owner))
