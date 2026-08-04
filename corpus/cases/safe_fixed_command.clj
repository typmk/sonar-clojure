(ns corpus.safe-fixed-command (:require [clojure.java.shell :as shell]))
(defn uptime [] (shell/sh "uptime"))
