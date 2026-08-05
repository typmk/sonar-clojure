(ns corpus.hooks.shell-injection (:require [clojure.java.shell :as shell]))
(defn ls [d] (shell/sh "sh" "-c" (str "ls " d)))
