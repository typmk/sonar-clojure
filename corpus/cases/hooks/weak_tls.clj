(ns corpus.hooks.weak-tls)
(defn ctx [] (javax.net.ssl.SSLContext/getInstance "TLSv1"))
