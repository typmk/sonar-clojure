(ns corpus.tenancy.safe-shared-taxonomy (:require [datomic.api :as d]))
(defn facet-count [db]
  (count (d/q '[:find ?e :where [?e :taxon/factor _]] db)))
