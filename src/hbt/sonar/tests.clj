(ns hbt.sonar.tests
  "Rules about the tests themselves.

  Java ships 48 of these; Clojure had one. A test that asserts nothing still
  runs, still passes, and still counts toward coverage -- so it raises the
  number everyone watches while checking nothing. On a codebase with 1,429
  `deftest` forms that is a lot of surface where the signal could be hollow
  and nothing would say so.

  Scoped to test files by the caller; these shapes are legitimate elsewhere."
  (:require [hbt.sonar.tree :as tree]))

(def rule-keys ["empty-test" "testing-without-assertion" "test-with-no-effect"])

(def ^:private assertions
  "`prop/for-all` is how a defspec asserts. Omitting it reported all fifteen
  of this project's own property tests as asserting nothing."
  #{"is" "are" "expect" "check" "thrown?" "thrown-with-msg?"
    "prop/for-all" "for-all" "prop/for-all*" "checking"})

(defn- asserts-inside? [nodes form]
  (some #(and (= :list (:tag %)) (contains? assertions (:head %)))
        (tree/children-of nodes form)))

(defn findings [nodes]
  (concat
   (for [n (tree/lists-headed-by nodes #{"deftest" "defspec"})
         :when (not (asserts-inside? nodes n))]
     {:rule "empty-test"
      :line (:line n) :col (:col n) :end-line (:end-line n) :end-col (:end-col n)
      :message "this test asserts nothing, so it passes whatever the code does"})

   (for [n (tree/lists-headed-by nodes #{"testing"})
         :when (not (asserts-inside? nodes n))]
     {:rule "testing-without-assertion"
      :line (:line n) :col (:col n) :end-line (:end-line n) :end-col (:end-col n)
      :message "this `testing` block contains no assertion"})

   (for [n (tree/lists-headed-by nodes #{"is"})
         :let [a (tree/first-argument nodes n)]
         :when (and a (= :list (:tag a))
                    (contains? #{"=" "not=" "==" "<" ">" "<=" ">="} (:head a))
                    (= 1 (count (tree/arguments nodes a))))]
     {:rule "test-with-no-effect"
      :line (:line n) :col (:col n) :end-line (:end-line n) :end-col (:end-col n)
      :message (str "(" (:head a) " x) with one operand is always true, so this assertion"
                    " cannot fail")})))
