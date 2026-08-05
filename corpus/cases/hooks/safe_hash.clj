(ns corpus.hooks.safe-hash)
(defn digest [b] (.digest (java.security.MessageDigest/getInstance "SHA-256") b))
