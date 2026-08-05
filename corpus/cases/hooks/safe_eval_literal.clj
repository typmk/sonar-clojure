(ns corpus.hooks.safe-eval-literal)
(defn warm [] (eval '(+ 1 1)))
