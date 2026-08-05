(ns corpus.hooks.safe-cipher)
(defn c [] (javax.crypto.Cipher/getInstance "AES/GCM/NoPadding"))
