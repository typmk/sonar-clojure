(ns corpus.hooks.insecure-random)
(defn token [] (rand-int 1000000))
