(ns corpus.hooks.cipher-ecb)
(defn c [] (javax.crypto.Cipher/getInstance "AES/ECB/PKCS5Padding"))
