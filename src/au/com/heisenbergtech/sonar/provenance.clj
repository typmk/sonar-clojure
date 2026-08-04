(ns au.com.heisenbergtech.sonar.provenance
  "Where this plugin's claims come from.

  Two of the artifact's assertions are about the outside world: that its
  generated rules match a particular clj-kondo, and that its CWE mappings were
  validated against a particular MITRE revision. Both were true when written
  and neither was recorded anywhere a build could check -- they lived in
  commit messages, which are narrative about the code rather than the code.

  Only ONE of those is stored. The clj-kondo version exists solely at
  generation time; at runtime neither the library nor deps.edn is reachable,
  so `provenance.edn` records it and nothing else. The rule count is a count
  of the shipped rules and the CWE revision is a field of the shipped
  catalogue -- reading them from the artifacts they describe is why a stored
  copy cannot drift from the original."
  (:require [clojure.edn :as edn]
            [au.com.heisenbergtech.sonar.classpath :as classpath]
            [au.com.heisenbergtech.sonar.cwe :as cwe]))

(def clj-kondo-version
  (delay (:clj-kondo-version
          (edn/read-string
           (slurp (classpath/required-resource
                   "au/com/heisenbergtech/sonar/provenance.edn"
                   "the generation record naming which clj-kondo this catalogue was built from"))))))

(def rule-count
  (delay (count (edn/read-string
                 (slurp (classpath/required-resource
                         "au/com/heisenbergtech/sonar/linters.edn"
                         "the generated rule catalogue"))))))

(defn summary
  "One line, for a log or a plugin description."
  []
  (str @rule-count " rules generated from clj-kondo " @clj-kondo-version
       "; CWE mappings checked against MITRE CWE v" (cwe/version)
       " (" (cwe/catalogue-date) ")"))
