(ns corpus.hooks.weak-cipher)
(defn c [] (javax.crypto.Cipher/getInstance "DES/CBC/PKCS5Padding"))
