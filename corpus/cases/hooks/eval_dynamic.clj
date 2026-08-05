(ns corpus.hooks.eval-dynamic)
(defn run [form] (eval form))
