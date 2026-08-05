(ns corpus.hooks.weak-hash)
(defn digest [b] (.digest (java.security.MessageDigest/getInstance "MD5") b))
