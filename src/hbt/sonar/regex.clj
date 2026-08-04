(ns hbt.sonar.regex
  "Regular-expression rules.

  Java ships 30 of these and Clojure had none, yet the exposure is identical:
  a Clojure regex literal compiles to the same `java.util.regex.Pattern` with
  the same backtracking engine. A pattern with nested quantifiers turns a
  short attacker-supplied string into seconds of CPU, which is a denial of
  service that needs no privilege and leaves no trace but latency.

  Detection is over the literal text, which is what the scanner has and what
  the engine will compile."
  (:require [clojure.string :as str]
            [hbt.sonar.tree :as tree]))

(def rule-keys ["redos-vulnerable-regex" "partial-match-validation"])

(def ^:private nested-quantifier
  "A quantified group whose body is itself quantified: (a+)+, (a*)*, ([a-z]+)*.
  The classic super-linear shape -- the engine retries every split of the
  inner match against every split of the outer."
  #"\((?:\?:)?[^()]*[+*][^()]*\)\s*[+*]")

(def ^:private quantified-alternation
  "(a|a)* and friends: overlapping alternatives under a quantifier give the
  engine an exponential number of equivalent paths to try."
  #"\((?:\?:)?[^()|]+\|[^()|]+\)\s*[+*]")

(defn- pattern-text
  "The source between the delimiters of a #\"...\" literal."
  [{:keys [text]}]
  (when (and text (str/starts-with? text "#\""))
    (subs text 2 (max 2 (dec (count text))))))

(defn- redos? [p]
  (boolean (or (re-find nested-quantifier p)
               (re-find quantified-alternation p))))

(def ^:private validating
  "Calls whose result decides whether input is acceptable. `re-find` succeeds
  on a PARTIAL match, so a pattern meant to validate a whole value accepts
  anything containing it -- \"evil.com/good.example\" passes a check written
  against `good\\.example`."
  #{"re-find" "re-seq" "re-matcher"})

(defn- anchored? [p]
  (and (str/starts-with? p "^") (str/ends-with? p "$")))

(defn findings [nodes]
  (concat
   (for [n nodes
         :when (and (= :regex (:type n)) (not (:commented? n)))
         :let [p (pattern-text n)]
         :when (and p (redos? p))]
     {:rule "redos-vulnerable-regex"
      :line (:line n) :col (:col n) :end-line (:end-line n) :end-col (:end-col n)
      :message (str "nested quantifier in " (:text n)
                    " -- a short crafted input can take exponential time")})

   ;; A regex that anchors both ends is clearly meant to match a whole value.
   ;; Handing it to re-find, which matches anywhere, silently weakens it to a
   ;; substring test.
   (for [l (tree/lists-headed-by nodes validating)
         :let [a (tree/first-argument nodes l)]
         :when (and a (= :regex (:type a)))
         :let [p (pattern-text a)]
         :when (and p (anchored? p) (not= "re-matches" (:head l)))]
     {:rule "partial-match-validation"
      :line (:line l) :col (:col l) :end-line (:end-line l) :end-col (:end-col l)
      :message (str (:head l) " matches anywhere in the string; the pattern is anchored,"
                    " so re-matches is what was meant")})))
