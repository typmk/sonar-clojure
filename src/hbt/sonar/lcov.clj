(ns hbt.sonar.lcov
  "Parses the lcov cloverage emits with --lcov.

  lcov over Cobertura because it is line-oriented and unambiguous: SF names a
  file, DA gives a line and its hit count, end_of_record closes the section.
  There is nothing to misread."
  (:require [clojure.string :as str]))

(defn parse
  "lcov text -> {filename {line hits}}. Later records for the same file merge
  by taking the higher hit count, which is what repeated runs mean."
  [text]
  (loop [[l & more] (str/split-lines (or text ""))
         file nil
         acc  {}]
    (if (nil? l)
      acc
      (let [line (str/trim l)]
        (cond
          (str/starts-with? line "SF:")
          (recur more (subs line 3) acc)

          (str/starts-with? line "DA:")
          (let [[ln hits] (str/split (subs line 3) #",")
                ln    (parse-long (str/trim (or ln "")))
                hits  (parse-long (str/trim (or hits "0")))]
            (if (and file ln hits)
              (recur more file (update-in acc [file ln] (fnil max 0) hits))
              (recur more file acc)))

          (= line "end_of_record")
          (recur more nil acc)

          :else (recur more file acc))))))

(defn covered-summary
  "For the sensor's own reporting: how many lines the report claims per file."
  [parsed]
  {:files (count parsed)
   :lines (reduce + 0 (map count (vals parsed)))
   :hit   (reduce + 0 (map (fn [m] (count (filter pos? (vals m)))) (vals parsed)))})
