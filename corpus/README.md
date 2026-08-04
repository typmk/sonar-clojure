# Corpus

Clojure files with planted, labelled weaknesses, and files that look like them
and are safe. `manifest.edn` says what each file should and should not produce.

It exists because every precision failure in this project was found by
accident. `redos-vulnerable-regex` scored 0 true positives out of 11 the first
time anyone measured it. `permissive-file-permissions` fired on 0700 and
ignored 0666. `empty-test` raised 19 findings against the first test suite it
met that used an assertion helper. In each case a test asserted the rule could
fire; nothing asserted where it must not.

A scanner that reports nothing is indistinguishable from a scanner that cannot
report. This is the only thing that tells them apart.

    clojure -M:corpus          # score every engine against the manifest

Hard negatives are the point. A rule that catches every vulnerable sample and
every safe one has 100% recall and is useless.
