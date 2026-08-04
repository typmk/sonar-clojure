(ns corpus.xss-raw (:require [hiccup.core :as h]))
(defn page [req] (h/raw (str "<b>" (get-in req [:params :name]) "</b>")))
