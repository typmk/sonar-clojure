(ns net.typemark.sonar.cwe
  "The MITRE CWE catalogue, shipped, so a mapping claim can be checked.

  Every security rule here asserts a CWE. Until now that assertion was
  checked once, by reading, and recorded in a commit message -- rank 4
  evidence about the code rather than the code itself. A wrong CWE is worse
  than none: it routes a finding to the wrong remediation guidance and
  inflates a compliance report that someone else relies on.

  MITRE publishes the answer. Since v4.2 each weakness carries a Mapping
  Notes Usage of Allowed, Allowed-with-Review, Discouraged or Prohibited --
  MITRE's own judgement on whether that entry may be the target of a mapping.
  Class-level entries like CWE-20 `Improper Input Validation` are Discouraged
  precisely because they are the ones everybody reaches for.

  Shipping the catalogue rather than querying it makes the check offline,
  reproducible and pinned: the version is a fact about the artifact, and a
  MITRE revision cannot silently change what this plugin claimed."
  (:require [clojure.data.json :as json]
            [net.typemark.sonar.classpath :as classpath]
            [net.typemark.sonar.const :as const]))

(def catalogue
  (delay (json/read-str (slurp (classpath/required-resource
                 const/cwe-resource
                 "the MITRE CWE catalogue every security rule mapping is checked against")))))

(defn version [] (get @catalogue "version"))
(defn catalogue-date [] (get @catalogue "date"))

(defn entry [id] (get-in @catalogue ["weaknesses" (str id)]))

(def permitted
  "MITRE's verdicts that permit an entry to be a mapping target. Anything
  else -- Discouraged, Prohibited, or an id absent from the catalogue -- is
  a mapping this plugin must not make."
  #{"Allowed" "Allowed-with-Review"})

(defn mappable?
  "Whether MITRE permits `id` as the target of a weakness mapping."
  [id]
  (contains? permitted (get (entry id) "usage")))

(defn violation
  "Why `id` is not a legitimate mapping target, or nil when it is."
  [id]
  (if-let [e (entry id)]
    (when-not (mappable? id)
      {:cwe id :usage (get e "usage") :abstraction (get e "abstraction")
       :name (get e "name")
       :reason (str "MITRE marks CWE-" id " as " (get e "usage")
                    " for mapping; choose a more specific weakness")})
    {:cwe id :reason (str "CWE-" id " is not in MITRE CWE v" (version))}))
