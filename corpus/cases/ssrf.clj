(ns corpus.ssrf (:require [clj-http.client :as client]))
(defn fetch [req] (client/get (get-in req [:params :url])))
