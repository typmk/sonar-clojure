(ns corpus.hard-via-map (:require [next.jdbc :as jdbc]))
(defn search [req db]
  (let [m {:sql (str "SELECT * FROM p WHERE n = '" (get-in req [:params :n]) "'")}]
    (jdbc/execute! db [(:sql m)])))
