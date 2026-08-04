(ns corpus.hard-thread-last (:require [next.jdbc :as jdbc]))
(defn search [req db]
  (->> (get-in req [:params :n])
       (str "SELECT * FROM p WHERE n = ")
       vector
       (jdbc/execute! db)))
