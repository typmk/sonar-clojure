(ns corpus.safe-parameterised (:require [next.jdbc :as jdbc]))
(defn search [req db]
  (jdbc/execute! db ["SELECT * FROM p WHERE n = ?" (get-in req [:params :n])]))
