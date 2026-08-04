(ns corpus.hard-destructured (:require [next.jdbc :as jdbc]))
(defn search [{{:keys [n]} :params} db]
  (jdbc/execute! db [(str "SELECT * FROM p WHERE n = '" n "'")]))
