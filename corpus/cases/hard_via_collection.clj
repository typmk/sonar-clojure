(ns corpus.hard-via-collection (:require [next.jdbc :as jdbc]))
(defn search [req db]
  (let [parts [(get-in req [:params :n])]]
    (jdbc/execute! db [(str "SELECT * FROM p WHERE n = '" (first parts) "'")])))
