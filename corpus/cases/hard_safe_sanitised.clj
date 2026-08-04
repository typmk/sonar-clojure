(ns corpus.hard-safe-sanitised
  (:require [hiccup.core :as h] [hiccup.util :as hu]))
(defn page [req]
  (h/raw (str "<b>" (hu/escape-html (get-in req [:params :name])) "</b>")))
