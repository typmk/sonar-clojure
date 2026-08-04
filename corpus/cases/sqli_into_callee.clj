(ns corpus.sqli-into-callee (:require [next.jdbc :as jdbc]))
(defn run! [db sql] (jdbc/execute! db [sql]))
(defn search [req db]
  (run! db (str "SELECT * FROM p WHERE n = '" (get-in req [:params :n]) "'")))
