(ns corpus.path-traversal (:require [clojure.java.io :as io]))
(defn read-doc [req] (slurp (io/file "/data" (get-in req [:params :f]))))
