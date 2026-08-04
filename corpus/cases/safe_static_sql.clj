(ns corpus.safe-static-sql (:require [next.jdbc :as jdbc]))
(defn all [db] (jdbc/execute! db ["SELECT * FROM p"]))
