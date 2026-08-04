(ns corpus.safe-sql-from-config (:require [next.jdbc :as jdbc]))
(def ^:private queries {:all "SELECT * FROM p"})
(defn run [db k] (jdbc/execute! db [(get queries k)]))
