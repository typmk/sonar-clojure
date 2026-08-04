(ns corpus.sqli-via-helper (:require [next.jdbc :as jdbc]))
(defn- build [t] (str "SELECT * FROM p WHERE n = '" t "'"))
(defn search [req db] (jdbc/execute! db [(build (get-in req [:params :n]))]))
