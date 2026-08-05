(ns corpus.hooks.safe-secure-random)
(defn token [] (.nextInt (java.security.SecureRandom.) 1000000))
