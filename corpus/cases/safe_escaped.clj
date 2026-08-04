(ns corpus.safe-escaped (:require [hiccup.util :as hu]))
(defn page [req] [:b (hu/escape-html (get-in req [:params :name]))])
