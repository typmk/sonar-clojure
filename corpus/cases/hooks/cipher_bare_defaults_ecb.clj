(ns corpus.hooks.cipher-bare-defaults-ecb)
(defn c [] (javax.crypto.Cipher/getInstance "AES"))
