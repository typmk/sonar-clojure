(ns net.typemark.sonar.security
  "Security rules as clj-kondo hooks.

  These were plugin-side rules that matched call heads as TEXT. Every false
  positive the audits measured came from that: a GraphQL client named `query`
  reported as SQL injection, `.exec` on a regex matcher reported as command
  injection, `MessageDigest` missed whenever it was not imported by the exact
  spelling the rule expected.

  A hook is keyed on the RESOLVED var. `clojure.java.shell/sh` fires only for
  that var, whatever it is aliased to, and never for a local of the same name.
  The resolution is clj-kondo's, which is the semantic model the plugin does
  not have and would otherwise have to rebuild.

  Findings carry a :type, which reaches the JSON report the SonarQube plugin
  already imports, so nothing downstream changes."
  (:require [clj-kondo.hooks-api :as api]))

(defn- literal?
  [n]
  (or (api/string-node? n)
      (api/keyword-node? n)
      (contains? #{:quote :syntax-quote} (api/tag n))
      (and (api/token-node? n)
           (let [v (try (api/sexpr n) (catch Exception _ ::x))]
             (or (number? v) (char? v) (boolean? v))))))

(defn- args [node] (rest (:children node)))

(defn- finding! [node type message]
  (api/reg-finding! (assoc (meta node) :type type :message message)))

(defn- str-arg
  [n]
  (when (and n (api/string-node? n))
    (try (api/sexpr n) (catch Exception _ nil))))

(defn weak-hash
  [{:keys [node]}]
  (when-let [a (str-arg (first (args node)))]
    (when (re-find #"(?i)^(MD5|SHA-?1|MD2|MD4)$" a)
      (finding! node :typemark/weak-hash-algorithm
                (str "broken hash algorithm " a)))))

(defn cipher
  [{:keys [node]}]
  (when-let [a (str-arg (first (args node)))]
    (cond
      (re-find #"(?i)/ECB/" a)
      (finding! node :typemark/cipher-ecb-mode
                "ECB mode encrypts identical blocks identically")

      (re-find #"(?i)^(DES|DESede|RC2|RC4|Blowfish)(/|$)" a)
      (finding! node :typemark/weak-cipher-algorithm
                (str "broken cipher algorithm " a))

      ;; SunJCE defaults a bare transformation to ECB. The plugin-side rule
      ;; could not see this, and it is the commonest real ECB bug on the JVM.
      (re-matches #"(?i)(AES|DESede|Blowfish)" a)
      (finding! node :typemark/cipher-ecb-mode
                (str a " with no mode defaults to ECB")))))

(defn tls-protocol
  [{:keys [node]}]
  (when-let [a (str-arg (first (args node)))]
    (when (re-find #"(?i)^(SSL|SSLv2|SSLv3|TLSv1|TLSv1\.1)$" a)
      (finding! node :typemark/weak-tls-protocol
                (str a " is an obsolete protocol")))))

(defn eval-call
  [{:keys [node]}]
  (let [a (first (args node))]
    (when (and a (not (literal? a)))
      (finding! node :typemark/eval-of-dynamic-value
                "eval on a computed value executes whatever it contains"))))

(defn read-string-call
  [{:keys [node]}]
  (finding! node :typemark/read-string-untrusted
            "clojure.core/read-string honours *read-eval*; use clojure.edn/read-string"))

(defn reflective
  [{:keys [node]}]
  (let [a (first (args node))]
    (when (and a (not (literal? a)))
      (finding! node :typemark/reflective-call
                "code is selected by a computed name"))))

(defn insecure-random
  [{:keys [node]}]
  (finding! node :typemark/insecure-random
            "delegates to java.util.Random; use SecureRandom for values an attacker must not guess"))

(defn shell
  [{:keys [node]}]
  (when (some #(not (literal? %)) (args node))
    (finding! node :typemark/shell-command-injection
              "a shell argument is built from a computed value")))

(defn- interpolating-str?
  "A str/format call with at least one non-literal argument.

  Both halves matter. Measured against lume/infra/ops.clj, checking for str
  ANYWHERE in the arguments flagged two correctly parameterised statements,
  and not requiring a computed argument flagged a third where `str` merely
  wraps three string literals across lines. Neither is injection."
  [n]
  (and (api/node? n)
       (api/list-node? n)
       (let [[h & as] (:children n)]
         (and h (api/token-node? h)
              (contains? (quote #{str format clojure.core/str clojure.core/format})
                         (try (api/sexpr h) (catch Exception _ nil)))
              (some #(not (literal? %)) as)))))

(defn sql
  "next.jdbc takes [sql & params]. Only the FIRST element is the statement;
  a computed value in a parameter position is exactly what should happen."
  [{:keys [node]}]
  (let [v (first (filter api/vector-node? (args node)))
        statement (first (:children v))]
    (when (and statement (interpolating-str? statement))
      (finding! node :typemark/sql-string-built
                "SQL statement is assembled by string building; pass parameters as values"))))
