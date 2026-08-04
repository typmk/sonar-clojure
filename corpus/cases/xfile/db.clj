(ns corpus.xfile.db (:require [next.jdbc :as jdbc]))
(defn run-raw! [db sql] (jdbc/execute! db [sql]))
