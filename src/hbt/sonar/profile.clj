(ns hbt.sonar.profile
  "The shipped quality profile. Everything clj-kondo does not default to
  :off is active, so the dashboard and a local `clj-kondo --lint` agree."
  (:require [hbt.sonar.const :as const]
            [hbt.sonar.rules :as rules]
            [hbt.sonar.concurrency :as concurrency]
            [hbt.sonar.interop :as interop]
            [hbt.sonar.security :as security])
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
    (doseq [r (distinct (map :key (concat security/rules interop/rules concurrency/rules)))
            :let [r {:key r}]]
      (.activateRule p const/repository-key (:key r)))
    (.done p)
    nil))
