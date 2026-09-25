(ns net.typemark.sonar.source
  "The source sensor's decisions that need no SensorContext, where they can be
  tested and measured; `net.typemark.sonar.source-sensor` keeps the calls
  that need the container."
  (:require [net.typemark.sift.registry :as registry]
            [net.typemark.sonar.metadata :as metadata]))

(defn sift-config
  "The sift linter configuration that runs exactly the rules in `active`, a
  set of Sonar rule keys. The quality profile is the one statement of what
  runs: a rule it leaves off is not computed, and one it turns on runs even
  where sift's own default level is :off.

  Returns {:config .. :unconfigured [rule ..]}. A rule that `:required`
  options cannot run from here, because nothing in Sonar supplies them."
  [active]
  (let [chosen (filter #(active (metadata/rule-key (:id %))) registry/built-in)
        [runnable unconfigured] ((juxt remove filter) :required chosen)
        level (fn [{:keys [id level]}]
                (if (or (nil? level) (= :off level))
                  (get registry/rulesets (keyword (namespace id)) :warning)
                  level))]
    {:config {:rulesets #{}
              :rules (into {} (for [r runnable] [(:id r) {:level (level r)}]))}
     :unconfigured (mapv :id unconfigured)}))
