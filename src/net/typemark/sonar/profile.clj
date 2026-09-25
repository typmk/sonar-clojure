(ns net.typemark.sonar.profile
  "The shipped quality profile. Everything clj-kondo does not default to
  :off is active, so the dashboard and a local `clj-kondo --lint` agree."
  (:require [net.typemark.sonar.const :as const]
            [net.typemark.sonar.metadata :as metadata]
            [net.typemark.sonar.rules :as rules]))

(set! *warn-on-reflection* true)

(defn define! [ctx]
  (let [p (.createBuiltInQualityProfile ctx const/profile-name const/language-key)]
    (.setDefault p true)
    (doseq [r (rules/catalogue)
            :when (not= :off (:level r))]
      (.activateRule p const/repository-key (:key r)))
    (.activateRule p const/repository-key const/unknown-rule)
    (doseq [r (metadata/load-rules (metadata/all-keys))
            :when (:activate? r)]
      (.activateRule p const/repository-key (:key r)))
    (.done p)
    nil))
