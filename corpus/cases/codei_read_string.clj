(ns corpus.codei-read-string)
(defn run [req] (eval (read-string (get-in req [:params :expr]))))
