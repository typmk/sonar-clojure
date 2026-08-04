(ns corpus.xfile.handler (:require [corpus.xfile.db :as db]))
(defn search [req conn]
  (db/run-raw! conn (str "SELECT * FROM p WHERE n = '" (get-in req [:params :n]) "'")))
