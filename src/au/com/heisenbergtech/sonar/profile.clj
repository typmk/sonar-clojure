(ns au.com.heisenbergtech.sonar.profile
  "The shipped quality profile. Everything clj-kondo does not default to
  :off is active, so the dashboard and a local `clj-kondo --lint` agree."
  (:require [au.com.heisenbergtech.sonar.const :as const]
            [au.com.heisenbergtech.sonar.metadata :as metadata]
            [au.com.heisenbergtech.sonar.rules :as rules])
  (:gen-class
   :name au.com.heisenbergtech.sonar.ClojureQualityProfile
   :implements [org.sonar.api.server.profile.BuiltInQualityProfilesDefinition]))

(set! *warn-on-reflection* true)

(defn -define [_ ctx]
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
