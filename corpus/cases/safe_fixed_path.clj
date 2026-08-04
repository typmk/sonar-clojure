(ns corpus.safe-fixed-path (:require [clojure.java.io :as io]))
(defn read-doc [] (slurp (io/file "/data" "README")))
