(ns corpus.hooks.safe-shell-literal (:require [clojure.java.shell :as shell]))
(defn up [] (shell/sh "uptime"))
