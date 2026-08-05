(ns corpus.hooks.reflective-call)
(defn lookup [n] (resolve (symbol n)))
