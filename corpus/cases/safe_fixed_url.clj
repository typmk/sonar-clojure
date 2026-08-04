(ns corpus.safe-fixed-url (:require [clj-http.client :as client]))
(defn fetch [] (client/get "https://api.internal/health"))
