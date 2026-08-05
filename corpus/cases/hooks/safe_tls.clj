(ns corpus.hooks.safe-tls)
(defn ctx [] (javax.net.ssl.SSLContext/getInstance "TLSv1.3"))
