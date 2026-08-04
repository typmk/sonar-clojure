(ns au.com.heisenbergtech.sonar.classpath
  "Resolving a resource that ships inside this plugin's jar.

  One function, its own namespace, because this is the mechanic that took a
  SonarQube server down. `clojure.java.io/resource` and Clojure's runtime
  both resolve through the THREAD CONTEXT classloader, which inside
  SonarQube's extension container is the web application's and cannot see
  the plugin jar. RulesDefinition.define got a nil URL, threw, and aborted
  platform startup into a restart loop.

  Three namespaces had grown their own copy of the fix. A mechanic with that
  failure mode belongs in exactly one place -- separate from what any
  particular caller happens to be loading, which is the concern the callers
  own."
  (:require [clojure.java.io :as io]))

(defn- own-loader
  "The classloader that defined this namespace's classes -- i.e. the plugin's,
  whatever the calling thread's context happens to be."
  ^ClassLoader []
  (.getClassLoader ^Class (class own-loader)))

(defn resource
  "The URL for a path inside the plugin jar, or nil."
  [path]
  (io/resource path (own-loader)))

(defn required-resource
  "The URL for a path that must be present, or a throw naming what is missing.

  A resource silently absent means a rule that never registers, and an issue
  raised against an unregistered rule is dropped without a message."
  [path explanation]
  (or (resource path)
      (throw (ex-info (str "sonar-clojure: " path " is missing from the plugin jar. " explanation)
                      {:path path}))))
