(ns hbt.sonar.metadata
  "Rule metadata as resources, in SonarSource's own layout.

  `org/sonar/l10n/<language>/rules/<repository>/<key>.json` beside a `.html`
  of the same name -- what `RuleMetadataLoader` in sonar-analyzer-commons
  reads, and what sonar-php ships 244 pairs of. This is a deliberate move of
  the metadata OUT of Clojure literals: a rule's title, severity, CWEs,
  remediation cost and prose are content, and content that lives in code
  cannot be edited, reviewed or translated without a rebuild.

  What stays in Clojure is the part that is genuinely code: the detection.

  Resources are resolved through the classloader that defined this namespace,
  not the thread context classloader -- inside SonarQube's extension
  container the latter is the web application's and cannot see this jar."
  (:require [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.string :as str]))

(def ^:private base "org/sonar/l10n/clj/rules/clj-kondo/")

(defn- own-loader ^ClassLoader []
  (.getClassLoader ^Class (class own-loader)))

(defn- resource [path]
  (io/resource path (own-loader)))

(defn load-rule
  "Metadata for one rule key, or nil when it ships no resource."
  [key]
  (when-let [j (resource (str base key ".json"))]
    (let [m (json/read-str (slurp j) :key-fn keyword)
          html (some-> (resource (str base key ".html")) slurp)]
      {:key key
       :name (:title m)
       :type (:type m)
       :severity (get-in m [:code :impacts :SECURITY]
                         (get-in m [:code :impacts :RELIABILITY]
                                 (get-in m [:code :impacts :MAINTAINABILITY] "MEDIUM")))
       :quality (cond (get-in m [:code :impacts :SECURITY]) "SECURITY"
                      (get-in m [:code :impacts :RELIABILITY]) "RELIABILITY"
                      :else "MAINTAINABILITY")
       :attribute (get-in m [:code :attribute] "CLEAR")
       :hotspot? (= "SECURITY_HOTSPOT" (:type m))
       :cwe (vec (get-in m [:securityStandards :CWE] []))
       :owasp (vec (get-in m [:securityStandards :OWASP] []))
       :remediation (get-in m [:remediation :constantCost] "10min")
       :tags (vec (:tags m))
       :html (or html "<p>No description shipped.</p>")})))

(defn load-rules
  "Metadata for every key given, failing loudly on one that ships no
  resource. A rule the detection can raise but the server never registered
  is an issue Sonar drops on the floor."
  [keys]
  (let [loaded (map (juxt identity load-rule) (distinct keys))
        missing (keep (fn [[k v]] (when-not v k)) loaded)]
    (when (seq missing)
      (throw (ex-info (str "sonar-clojure: no rule metadata resource for " (str/join ", " missing)
                           ". Every rule the detection can raise must ship "
                           base "<key>.json and .html")
                      {:missing (vec missing)})))
    (mapv second loaded)))
