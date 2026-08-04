(ns corpus.sqli-direct (:require [next.jdbc :as jdbc]))
(defn search [req db]
  (jdbc/execute! db [(str "SELECT * FROM p WHERE n = '" (get-in req [:params :n]) "'")]))
