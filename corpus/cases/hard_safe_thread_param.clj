(ns corpus.hard-safe-thread-param (:require [next.jdbc :as jdbc]))
(defn search [req db]
  (->> ["SELECT * FROM p WHERE n = ?" (get-in req [:params :n])]
       (jdbc/execute! db)))
