(ns corpus.hard-multi-arity (:require [next.jdbc :as jdbc]))
(defn run!
  ([db sql] (run! db sql nil))
  ([db sql _opts] (jdbc/execute! db [sql])))
(defn search [req db]
  (run! db (str "SELECT * FROM p WHERE n = '" (get-in req [:params :n]) "'")))
