(ns net.typemark.sonar.kondo
  "Everything about a clj-kondo report that does not need a SensorContext.

  Sonar does not publish SensorContextTester for the 13.x/26.x line (checked:
  sonar-plugin-api, -impl, -test-fixtures, sonar-scanner-engine, sonar-core),
  so the decisions live here where they can be tested, and the sensor keeps
  only the calls that need the container."
  (:require [clojure.data.json :as json]
            [clojure.string]
            [net.typemark.sonar.const :as const]))

(defn findings
  "Parse a clj-kondo JSON report into normalised finding maps."
  [report-text]
  (->> (get (json/read-str report-text) "findings")
       (mapv (fn [f]
               {:filename (get f "filename")
                :type     (get f "type")
                :level    (get f "level")
                :message  (get f "message")
                :row      (get f "row")
                :col      (get f "col")
                :end-row  (get f "end-row")
                :end-col  (get f "end-col")}))))

(defn hook-rule
  "The Sonar rule key of a hook finding, or nil for any other linter. Hook
  findings arrive as :typemark/weak-hash-algorithm; the Sonar rule key is
  weak-hash-algorithm. We own that namespace, so strip it."
  [t]
  (let [p const/hook-linter-prefix]
    (when (and t (clojure.string/starts-with? t p)) (subs t (count p)))))

(defn- normalise [t] (or (hook-rule t) t))

(defn classify
  "Pick the rule a finding is filed under. A linter absent from the catalogue
  files under the catch-all with its real name kept in the message, because a
  finding that vanishes is worse than one filed imprecisely."
  [known {:keys [type message]}]
  (let [type (normalise type)]
   (if (contains? known type)
    {:rule type :message message :recognised? true}
    {:rule const/unknown-rule
     :message (str "[" type "] " message)
     :recognised? false})))

(defn span
  "clj-kondo positions -> Sonar positions. Lines are 1-based in both; columns
  are 1-based in clj-kondo and 0-based offsets in Sonar. A finding with no
  usable end position selects its whole line."
  [{:keys [row col end-row end-col]}]
  (let [line (max 1 (or row 1))
        c    (max 1 (or col 1))]
    (if (and end-row end-col
             (or (> end-row line)
                 (and (= end-row line) (> end-col c))))
      {:line line
       :start-offset (dec c)
       :end-line (max line end-row)
       :end-offset (max 0 (dec end-col))}
      {:line line})))

(defn whole-line?
  "True when the span could not be narrowed to a range."
  [s]
  (nil? (:start-offset s)))
