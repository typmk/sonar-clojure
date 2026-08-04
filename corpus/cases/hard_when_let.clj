(ns corpus.hard-when-let (:require [next.jdbc :as jdbc]))
(defn search [req db]
  (when-let [n (get-in req [:params :n])]
    (jdbc/execute! db [(str "SELECT * FROM p WHERE n = '" n "'")])))
