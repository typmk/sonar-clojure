(ns corpus.tenancy.safe-pull-by-eid (:require [datomic.api :as d]))
(defn fetch [db eid] (d/pull db '[*] eid))
