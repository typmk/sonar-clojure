(ns hbt.sonar.profile
  "The shipped quality profile. Everything clj-kondo does not default to
  :off is active, so the dashboard and a local `clj-kondo --lint` agree."
  (:require [hbt.sonar.const :as const]
            [hbt.sonar.rules :as rules])
  (:gen-class
   :name hbt.sonar.ClojureQualityProfile
   :implements [org.sonar.api.server.profile.BuiltInQualityProfilesDefinition]))

(defn -define [_ ctx]
  (let [p (.createBuiltInQualityProfile ctx const/profile-name const/language-key)]
    (.setDefault p true)
    (doseq [r (rules/catalogue)
            :when (not= :off (:level r))]
      (.activateRule p const/repository-key (:key r)))
    (.activateRule p const/repository-key const/unknown-rule)
    (.done p)
    nil))
