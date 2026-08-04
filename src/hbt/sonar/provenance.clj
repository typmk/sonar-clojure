(ns hbt.sonar.provenance
  "Where this plugin's claims come from.

  Two of the artifact's assertions are about the outside world: that its 136
  generated rules match a particular clj-kondo, and that its CWE mappings were
  validated against a particular MITRE revision. Both were true when written
  and neither was recorded anywhere a build could check -- they lived in
  commit messages, which are narrative about the code rather than the code.

  Stamped at generation time and read back here, they become facts about the
  artifact: assertable in a test, printable in a log, and visible in the
  SonarQube UI through the plugin description."
  (:require [clojure.edn :as edn]
            [hbt.sonar.classpath :as classpath]))

(def record
  (delay (edn/read-string
          (slurp (classpath/required-resource
                  "hbt/sonar/provenance.edn"
                  "the generation record naming which clj-kondo and which MITRE CWE revision this catalogue was built from")))))

(defn summary
  "One line, for a log or a plugin description."
  []
  (let [{:keys [rule-catalogue cwe-catalogue]} @record]
    (str (:rules rule-catalogue) " rules generated from clj-kondo "
         (:clj-kondo-version rule-catalogue)
         "; CWE mappings checked against MITRE CWE v" (:version cwe-catalogue)
         " (" (:date cwe-catalogue) ")")))
