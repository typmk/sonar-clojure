(ns corpus.tenancy.unscoped-document-query (:require [datomic.api :as d]))
(defn all-invoices [db]
  (d/q '[:find ?e :where [?e :document/type :invoice]] db))
