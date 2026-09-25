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

    clojure -M:corpus          # score every engine; non-zero on a regression, and CI runs it

Hard negatives are the point. A rule that catches every vulnerable sample and
every safe one has 100% recall and is useless.

## Engines

Three engines are scored, and their union — because none is the answer alone.
opengrep sees within a file; this plugin's `callgraph` pass sees across them,
over clj-kondo's whole-project analysis; `kondo` is the security hooks.
Measured across lume, sur and forma: **26 files hold a source and 46 hold a
sink, and only 4 hold both**, so an intra-file engine can examine 4 files out
of 181 there. 53 cases, measured 2026-09-25:

```
opengrep    TP 16  FN 12  FP 0    recall  57.1%   precision 100.0%
callgraph   TP  3  FN 25  FP 0    recall  10.7%   precision 100.0%
kondo       TP 19  FN  9  FP 0    recall  67.9%   precision 100.0%
union       TP 28  FN  0  FP 0    recall 100.0%   precision 100.0%
```

Each engine alone misses cases that are another's job, so CI reports each and
gates only the union. The callgraph's low recall is not a defect: it only
reports paths that cross a function boundary.

Against 39,307 lines of real Clojure the taint rules reported **0 findings and
0 false positives**. That reading only means something because of the corpus:
without it, nothing distinguishes a clean codebase from a blind scanner.

## Known misses

A miss is recorded in `manifest.edn` as `:known-miss` rather than removed — a
failing case deleted stops being evidence, and one that blocks every build gets
deleted. opengrep has two, both caught by the union:

- **Nested map destructuring** (`hard_destructured.clj`) — `{{:keys [n]} :params}`
  matches nothing in opengrep's pattern language, in taint mode or plain
  search. Destructured ring handlers are idiomatic.
- **A flow across two files** (`xfile/handler.clj`) — opengrep's taint is
  intra-file.

`->>` threading was a known miss too, closed, and it cost the most: 97 `->>` and 103 `->`
across this organisation's Clojure. It turned out not to be a dataflow gap at
all — the sink pattern required a literal `[sql ...]` argument, and under
threading the vector arrives through the macro. Matching the threaded shape
closed it, at the cost of one false positive on a correctly parameterised
threaded call, which `pattern-not` on a leading string literal then removed.

## Blind cases

Writing the corpus after the rules, in the same hour, proves little; the eight
cases added blind are the ones that carried information. Three of them failed,
and one was a false positive on correctly sanitised code — the sanitiser list
named `hiccup.util/escape-html` and bare `escape-html` but not `hu/escape-html`,
which is how it is actually written.
