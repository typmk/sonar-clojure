(ns hbt.sonar.interop
  "Security rules for the Java libraries Clojure calls.

  The premise: Clojure runs on the JDK and reaches for the same
  `MessageDigest`, `Cipher`, `SSLContext`, `DocumentBuilderFactory` and
  `ObjectInputStream` as Java does, so it inherits the same CVE classes.
  Sonar's Java analyzer cannot see any of it -- it parses Java source, and
  measured against this server its 720 rules share no repository with Scala's
  41 or Kotlin's 145. Each JVM language pays for its own.

  What it does NOT try to reproduce: the Java rules about Java's syntax --
  null dereference, equals/hashCode, try-with-resources, mutable statics.
  Those are meaningless here. Nor most of Java's concurrency rules, since
  Clojure's defaults are immutable; the concurrency hazards Clojure DOES have
  are its own, and live in hbt.sonar.concurrency.

  Class names are resolved through the ns form's :import, so both
  `(MessageDigest/getInstance ...)` and
  `(java.security.MessageDigest/getInstance ...)` match the same rule."
  (:require [clojure.string :as str]
            [hbt.sonar.tree :as tree]))

;; ---------------------------------------------------------------------------
;; Import resolution.

(defn imports
  "simple class name -> fully qualified, from the ns form's :import clauses.
  Handles both `[java.security MessageDigest Signature]` and a bare
  `java.util.Random`."
  [nodes]
  (let [import-forms (tree/lists-headed-by nodes #{":import"})]
    (reduce
     (fn [acc form]
       (let [kids (remove #(= :trivia (:type %)) (tree/children-of nodes form))]
         (reduce
          (fn [a n]
            (cond
              ;; [package Class Class]
              (= :vector (:tag n))
              (let [syms (->> (tree/children-of nodes n)
                              (filter #(= :symbol (:type %)))
                              (map :text))]
                (if-let [pkg (first syms)]
                  (reduce (fn [m c] (assoc m c (str pkg "." c))) a (rest syms))
                  a))

              ;; bare java.util.Random
              (and (= :symbol (:type n)) (str/includes? (:text n) "."))
              (assoc a (last (str/split (:text n) #"\.")) (:text n))

              :else a))
          acc kids)))
     {} import-forms)))

(defn- resolve-class
  "A class name as written -> fully qualified, if we can tell."
  [imported nm]
  (cond
    (nil? nm) nil
    (str/includes? nm ".") nm
    :else (get imported nm)))

;; ---------------------------------------------------------------------------
;; The rule table. Each entry is data: a class, a member, and optionally a
;; predicate over the first string argument.

(def rules
  [{:key "weak-hash-algorithm" :class "java.security.MessageDigest" :member "getInstance"
    :arg #"(?i)^(MD5|SHA-?1|MD2|MD4)$"
    :name "Broken hash algorithm"
    :cwe [327 328] :owasp ["A2"] :severity "HIGH"
    :doc "<p>MD5 and SHA-1 are broken for any security purpose.</p>"
    :fix "<pre>(MessageDigest/getInstance \"SHA-256\")</pre>"}

   {:key "cipher-ecb-mode" :class "javax.crypto.Cipher" :member "getInstance"
    :arg #"(?i)/ECB/"
    :name "ECB mode leaks plaintext structure"
    :cwe [327] :owasp ["A2"] :severity "HIGH"
    :doc "<p>ECB encrypts identical blocks identically, so structure survives encryption.</p>"
    :fix "<pre>(Cipher/getInstance \"AES/GCM/NoPadding\")</pre>"}

   {:key "weak-cipher-algorithm" :class "javax.crypto.Cipher" :member "getInstance"
    :arg #"(?i)^(DES|DESede|RC2|RC4|Blowfish)(/|$)"
    :name "Broken cipher algorithm"
    :cwe [327] :owasp ["A2"] :severity "HIGH"
    :doc "<p>DES, 3DES, RC2, RC4 and Blowfish are not acceptable for new work.</p>"
    :fix "<pre>(Cipher/getInstance \"AES/GCM/NoPadding\")</pre>"}

   {:key "weak-tls-protocol" :class "javax.net.ssl.SSLContext" :member "getInstance"
    :arg #"(?i)^(SSL|SSLv2|SSLv3|TLSv1|TLSv1\.1)$"
    :name "Obsolete TLS protocol"
    :cwe [326 327] :owasp ["A2"] :severity "HIGH"
    :doc "<p>Everything below TLS 1.2 is broken in the field.</p>"
    :fix "<pre>(SSLContext/getInstance \"TLSv1.3\")</pre>"}

   {:key "insecure-random" :class "java.util.Random" :member :new
    :name "java.util.Random is predictable"
    :cwe [338 330] :owasp ["A2"] :severity "MEDIUM"
    :doc "<p>Use <code>java.security.SecureRandom</code> for anything an attacker must not guess.</p>"
    :fix "<pre>(java.security.SecureRandom.)</pre>"}

   {:key "unsafe-deserialization" :class "java.io.ObjectInputStream" :member :new
    :name "Java deserialization of untrusted data"
    :cwe [502] :owasp ["A8"] :severity "HIGH"
    :doc "<p>Java deserialization executes attacker-chosen gadget chains.</p>"
    :fix "<p>Use a data format that does not instantiate arbitrary classes.</p>"}

   {:key "unsafe-deserialization" :class "java.beans.XMLDecoder" :member :new
    :name "XMLDecoder deserialization"
    :cwe [502] :owasp ["A8"] :severity "HIGH"
    :doc "<p><code>XMLDecoder</code> instantiates and invokes whatever the document names.</p>"
    :fix "<p>Parse to data and construct the object yourself.</p>"}

   {:key "jndi-injection" :class "javax.naming.InitialContext" :member "doLookup"
    :name "JNDI lookup"
    :cwe [74 502] :owasp ["A3"] :severity "HIGH"
    :doc "<p>A JNDI name the caller influences fetches and executes remote code -- the Log4Shell class of bug.</p>"
    :fix "<p>Never build a JNDI name from input.</p>"}

   {:key "predictable-temp-file" :class "java.io.File" :member "createTempFile"
    :name "Predictable temporary file"
    :cwe [377] :owasp ["A1"] :severity "MEDIUM"
    :doc "<p>The classic create-then-open race lets a local attacker win the name.</p>"
    :fix "<pre>(java.nio.file.Files/createTempFile ...)</pre>"}

   ;; --- hotspots: the call is legitimate, the configuration is what matters
   {:key "xml-external-entity" :class "javax.xml.parsers.DocumentBuilderFactory" :member "newInstance"
    :hotspot? true :name "XML parser should disable external entities"
    :cwe [611] :owasp ["A5"] :severity "MEDIUM"
    :doc "<p>Confirm <code>disallow-doctype-decl</code> is set, or the parser fetches attacker-named URLs and reads local files.</p>"}

   {:key "xml-external-entity" :class "javax.xml.parsers.SAXParserFactory" :member "newInstance"
    :hotspot? true :name "SAX parser should disable external entities"
    :cwe [611] :owasp ["A5"] :severity "MEDIUM"
    :doc "<p>Confirm external entity resolution is disabled.</p>"}

   {:key "xml-external-entity" :class "javax.xml.transform.TransformerFactory" :member "newInstance"
    :hotspot? true :name "Transformer should disable external entities"
    :cwe [611] :owasp ["A5"] :severity "MEDIUM"
    :doc "<p>Confirm <code>ACCESS_EXTERNAL_DTD</code> and <code>ACCESS_EXTERNAL_STYLESHEET</code> are empty.</p>"}

   {:key "xml-external-entity" :class "javax.xml.stream.XMLInputFactory" :member "newInstance"
    :hotspot? true :name "StAX parser should disable external entities"
    :cwe [611] :owasp ["A5"] :severity "MEDIUM"
    :doc "<p>Confirm <code>SUPPORT_DTD</code> is false.</p>"}

   {:key "trust-all-certificates"
    :name "Certificate validation disabled"
    :cwe [295 297] :owasp ["A2"] :severity "HIGH"
    :doc (str "<p>A <code>TrustManager</code> that accepts every chain, or a "
              "<code>HostnameVerifier</code> that accepts every name, turns TLS into "
              "encryption without authentication -- any machine on the path can read "
              "and rewrite the traffic.</p>")
    :fix "<p>Trust a pinned CA for the host instead of disabling the check.</p>"}

   {:key "shell-invocation" :class "java.lang.ProcessBuilder" :member :new
    :hotspot? true :name "Process invocation should be reviewed"
    :cwe [78] :owasp ["A3"] :severity "MEDIUM"
    :doc "<p>Confirm no part of the command line is caller-controlled.</p>"}])

(def ^:private by-target
  (reduce (fn [m r] (update m [(:class r) (:member r)] (fnil conj []) r)) {} rules))

(defn- matches? [nodes lst {:keys [arg]}]
  (or (nil? arg)
      (when-let [s (tree/unquote-string (tree/first-argument nodes lst))]
        (boolean (re-find arg s)))))

(def ^:private trust-types
  #{"X509TrustManager" "TrustManager" "X509ExtendedTrustManager" "HostnameVerifier"
    "javax.net.ssl.X509TrustManager" "javax.net.ssl.TrustManager"
    "javax.net.ssl.X509ExtendedTrustManager" "javax.net.ssl.HostnameVerifier"})

(defn- trust-all-findings
  "A reify/proxy of a TrustManager or HostnameVerifier. There is no safe
  reason to implement these by hand in application code: the JDK's default
  already does the checking, and overriding it exists to switch it off."
  [nodes]
  (for [n (tree/lists-headed-by nodes #{"reify" "proxy"})
        :when (some #(and (= :symbol (:type %)) (contains? trust-types (:text %)))
                    (tree/children-of nodes n))]
    {:rule "trust-all-certificates"
     :line (:line n) :col (:col n) :end-line (:end-line n) :end-col (:end-col n)
     :message "hand-written TrustManager/HostnameVerifier -- confirm it does not accept every certificate"}))

(defn findings
  "Java-interop security findings for one parsed file."
  [nodes]
  (let [imported (imports nodes)]
    (for [n nodes
          :when (and (= :list (:tag n)) (not (:commented? n)) (:head n))
          :let [[cls member] (tree/head-parts (:head n))
                fq (resolve-class imported cls)]
          :when fq
          r (concat (get by-target [fq member]) (get by-target [fq :new]))
          :when (and (or (= (:member r) member)
                         (and (= :new (:member r)) (= :new member)))
                     (matches? nodes n r))]
      {:rule (:key r)
       :line (:line n) :col (:col n)
       :end-line (:end-line n) :end-col (:end-col n)
       :message (str (:name r) " -- " fq
                     (when (string? member) (str "/" member)))})))

(defn all-findings [nodes]
  (concat (findings nodes) (trust-all-findings nodes)))
