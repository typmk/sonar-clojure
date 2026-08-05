(ns corpus.hooks.safe-resolve-literal)
(defn lookup [] (resolve 'clojure.core/inc))
