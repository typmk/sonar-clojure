(ns corpus.hard-anon-fn (:require [next.jdbc :as jdbc]))
(defn search [req db]
  ((fn [t] (jdbc/execute! db [(str "SELECT * FROM p WHERE n = '" t "'")]))
   (get-in req [:params :n])))
