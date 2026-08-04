(ns corpus.cmdi-direct (:require [clojure.java.shell :as shell]))
(defn ls [req] (shell/sh "sh" "-c" (str "ls " (get-in req [:params :d]))))
