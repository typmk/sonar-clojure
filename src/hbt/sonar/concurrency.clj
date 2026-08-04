(ns hbt.sonar.concurrency
  "The concurrency hazards Clojure actually has.

  Most of Java's concurrency rules do not port: there is no `synchronized`
  to forget, no `volatile` to miss, no double-checked locking to get wrong,
  and shared data is immutable by default. That is the language doing its
  job, and reproducing those rules here would be theatre.

  What survives is narrower and specific to Clojure's coordination
  primitives, and it is the kind of defect that passes every test on a quiet
  machine and only appears under contention."
  (:require [hbt.sonar.tree :as tree]))

(def rules
  [{:key "side-effect-in-swap"
    :name "Side effect inside a retrying update"
    :cwe [] :owasp [] :severity "HIGH" :quality "RELIABILITY"
    :doc (str "<p><code>swap!</code>, <code>alter</code>, <code>commute</code> and "
              "<code>swap-vals!</code> retry their function under contention, so any "
              "side effect inside it happens more than once -- silently, and only "
              "when two threads meet.</p>")
    :fix (str "<p>Make the update function pure and perform the effect on its result:</p>"
              "<pre>(let [v (swap! a f)]\n  (notify! v))</pre>")}

   {:key "discarded-future"
    :name "Future whose value is never taken"
    :cwe [] :owasp [] :severity "MEDIUM" :quality "RELIABILITY"
    :doc (str "<p>A <code>future</code> whose result is discarded swallows its exception: "
              "the throw is held until someone derefs, and nobody does. The work appears "
              "to succeed.</p>")
    :fix "<p>Deref it, or use an executor that reports failures.</p>"}])

(def ^:private retrying #{"swap!" "swap-vals!" "alter" "commute" "alter-var-root"})

(def ^:private effectful
  "Calls whose whole point is the effect. Deliberately short: a false
  positive here accuses correct code of a race that is not there."
  #{"println" "print" "prn" "pr" "spit" "slurp" "log/info" "log/warn" "log/error"
    "log/debug" "send" "send-off" "deliver" "reset!" "swap!" "conj!" "assoc!"
    "dissoc!" "disj!" "persistent!" "future" "sh" "execute!" "insert!" "delete!"
    "http/post" "http/get" "printf" "flush"})

(defn- effectful-call-inside? [nodes form]
  (some #(and (= :list (:tag %))
              (contains? effectful (:head %)))
        (tree/children-of nodes form)))

(defn findings
  "Concurrency findings for one parsed file."
  [nodes]
  (concat
   (for [n (tree/lists-headed-by nodes retrying)
         :when (effectful-call-inside? nodes n)]
     {:rule "side-effect-in-swap"
      :line (:line n) :col (:col n) :end-line (:end-line n) :end-col (:end-col n)
      :message (str (:head n) " retries under contention, so the side effect inside it"
                    " can happen more than once")})

   ;; A future in expression position whose value is used is fine. One that
   ;; is a statement -- a direct child of a do/when/let body -- is not.
   (for [n (tree/lists-headed-by nodes #{"future"})
         :let [parent (->> nodes
                           (filter #(and (= :list (:tag %))
                                         (< (:depth %) (:depth n))
                                         (<= (:line %) (:line n))
                                         (>= (:end-line %) (:end-line n))))
                           (sort-by :depth)
                           last)]
         :when (and parent (contains? #{"do" "when" "when-let" "doseq" "dotimes"} (:head parent)))]
     {:rule "discarded-future"
      :line (:line n) :col (:col n) :end-line (:end-line n) :end-col (:end-col n)
      :message "the value of this future is discarded, so an exception inside it is never seen"})))
