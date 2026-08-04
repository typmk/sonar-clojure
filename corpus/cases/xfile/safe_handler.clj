(ns corpus.xfile.safe-handler (:require [corpus.xfile.db :as db]))
(defn all [conn] (db/run-raw! conn "SELECT * FROM p"))
