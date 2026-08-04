# sonar-clojure

A SonarQube analyzer for Clojure. It claims `.clj`, `.cljs`, `.cljc`, `.edn` and
`.bb` files so SonarQube indexes them, and supplies rules, size and complexity
measures, duplication, syntax highlighting, a symbol table, coverage and test
results over them.

SonarQube ships no Clojure support. Without a language claiming these files
nothing is indexed, so no finding — from this plugin or any other source — can
be attached to them.

---

## Status

Running on SonarQube 26.7 (Community Build). The measurements below are from
this plugin analysing its own source, on that server.

| | |
|---|---|
| Rules | **291** — 170 in `clj-kondo`, 121 in `external_splint` |
| By type | 18 vulnerability · 10 security hotspot · 63 bug · 200 code smell |
| Requires | SonarQube 10.0+ (verified only against 26.7), JRE 17+ |
| Built against | `sonar-plugin-api` 13.9.0.4428 |
| Artifact | ~7 MB — the Clojure runtime is shaded in |

Two rules ship **registered but inactive**: `unscoped-tenant-query` and
`partial-match-validation`. Their precision on real code is not yet good enough
to justify switching them on for everyone. Enable them per-project if the
tradeoff suits you.

---

## Install

```bash
cp sonar-clojure-plugin-0.1.0.jar $SONARQUBE_HOME/extensions/plugins/
# restart SonarQube
```

Docker:

```bash
docker cp sonar-clojure-plugin-0.1.0.jar sonarqube:/opt/sonarqube/extensions/plugins/
docker restart sonarqube
```

Confirm it registered:

```bash
curl -s "$SONAR_URL/api/languages/list" | grep clj
```

---

## Configure

Everything works with defaults; each property below only needs setting if your
build writes somewhere else.

```properties
# sonar-project.properties
sonar.projectKey=my-project
sonar.sources=src
sonar.tests=test

# reports (defaults shown)
sonar.clojure.kondo.reportPaths=target/clj-kondo.json
sonar.clojure.kondo.analysisPaths=target/clj-kondo-analysis.json
sonar.clojure.cloverage.reportPaths=target/coverage/codecov.json
sonar.clojure.kaocha.reportPaths=target/junit.xml

# file selection (defaults shown)
sonar.clj.file.suffixes=.clj,.cljs,.cljc,.edn,.bb
sonar.clj.file.patterns=**/*.clj,**/*.cljs,**/*.cljc,**/*.edn,**/*.bb

# optional external analyzers — no default; unset means not run
sonar.clojure.splint.reportPaths=target/splint.json
sonar.clojure.cljholmes.reportPaths=target/clj-holmes.json
sonar.clojure.eastwood.reportPaths=target/eastwood.json
sonar.clojure.nvd.reportPaths=target/nvd.json
```

The suffix and pattern properties are keyed by **language key** (`clj`), which
is the convention SonarQube's scanner reads — the same shape as
`sonar.java.file.suffixes`.

---

## Produce the reports

The plugin reads reports; it does not invoke the tools. Your CI lints and tests
once, and both the local gate and the dashboard use that same output.

```bash
# rules and symbol navigation
clj-kondo --lint src test --config '{:output {:format :json}}' \
  > target/clj-kondo.json
clj-kondo --lint src test \
  --config '{:output {:format :json :analysis {:locals true}}}' \
  > target/clj-kondo-analysis.json

# coverage — codecov.json, NOT lcov (see below)
clojure -M:coverage --codecov -p src -s test

# test results, via the kaocha-junit-xml plugin
bin/kaocha --plugin kaocha.plugin/junit-xml --junit-xml-file target/junit.xml
```

**Use cloverage's `--codecov` output, not `--lcov`.** cloverage's lcov writer
emits `DA:<line>,<covered-form-count>`, so a line where one form of five ran is
recorded as covered. Measured on this project, 22 of 451 instrumented lines were
partial and every one read as fully covered. `codecov.json` preserves the
distinction and partial lines become conditions. lcov is still accepted, with a
warning.

A missing report is reported loudly rather than treated as a clean result.

---

## What it analyses

**Rules.** 136 are generated from clj-kondo's own default configuration, so a
clj-kondo upgrade adds rules mechanically and the two cannot drift. A finding
from a linter newer than the plugin files under a catch-all carrying its real
name rather than disappearing. 33 more are hand-written, covering weakness
classes clj-kondo does not: JDK library misuse (broken crypto, ECB, obsolete
TLS, deserialization, JNDI, XXE, certificate validation), injection and
credential exposure, ReDoS, `clojure.test` quality, and the Clojure-specific
concurrency hazards immutability does not remove — a side effect inside a
retrying `swap!`, a `future` whose value is discarded.

Every hand-written rule carries its CWE and OWASP category, validated against
MITRE CWE v4.20.

**Measures.** ncloc, comment lines, functions, classes, statements, cyclomatic
and cognitive complexity, plus the per-line `ncloc` and executable-lines data
SonarQube uses to compute coverage on new code. Where a coverage report exists,
the executable set is taken from it rather than inferred.

**Also** duplication tokens (literals collapsed, so blocks differing only in
constants still match), syntax highlighting, and a symbol table built from
clj-kondo's analysis so declarations and references link in the code viewer.

**External analyzers.** splint, clj-holmes, eastwood and nvd-clojure findings
import as external issues. splint's 121 rules ship as a catalogue and are
browsable in the Rules UI before the tool has ever run.

---

## Limitations

Stated plainly, because a security tool that overstates itself is worse than
none.

- **Taint tracking is not a taint engine.** It follows a value from a known
  source to a known sink within one form, and across a call graph derived from
  clj-kondo's analysis. It does not track argument positions, so the
  interprocedural rule over-approximates and says so in its own description.
  SonarSource's taint engine is closed to third-party plugins.
- **No semantic model.** Analysis is over a concrete syntax tree from rewrite-clj
  plus clj-kondo's analysis output. There is no type inference and no symbol
  resolution beyond what clj-kondo provides.
- **rewrite-clj is stricter than Clojure's reader** in rare cases. A file it
  cannot parse contributes no measures, and raises an analysis error naming
  the file rather than failing silently.
- **Verified against SonarQube 26.7 only.** The `Sonar-Version: 10.0` floor in
  the manifest is a declaration, not a tested claim.
- Java's `javasecurity` (taint) rules are Developer Edition; nothing here
  substitutes for them.

---

## Build from source

```bash
clojure -X:gen-rules     # regenerate the rule catalogue from clj-kondo
clojure -T:build uber    # -> target/sonar-clojure-plugin-0.1.0.jar
clojure -M:test          # 80 tests, 259 assertions
```

The entry point is Java, not Clojure, and must stay that way: Clojure's runtime
resolves `clojure/core.clj` through the thread context classloader, which inside
SonarQube's plugin container cannot see the plugin jar. Loading a `gen-class`
artifact is itself what triggers the runtime, so the classloader has to be
corrected by a class carrying no Clojure static initialiser.

Rule metadata lives in `resources/org/sonar/l10n/clj/rules/clj-kondo/<key>.json`
beside a `.html` of the same name — SonarSource's own layout. Titles, severities,
CWEs, remediation costs and prose are edited there, without recompiling.

---

## Licence

**Eclipse Public License 2.0.** Full text in [LICENSE](LICENSE); attribution
for redistributed components in [NOTICE](NOTICE).

EPL because the jar bundles the Clojure runtime, which is EPL-1.0 — the same
licence family, so there is no compatibility question. It is also what the
Clojure ecosystem uses, and weak enough (file-level copyleft) to be adopted
without a legal review.

`sonar-plugin-api` is LGPL-3.0, which is what SonarSource's own analyzers use.
It is a *provided* dependency: the plugin jar contains no `org/sonar/api`
classes and SonarQube supplies them at runtime, so no LGPL obligation attaches
to this work. Licensing this plugin LGPL to match its peers would have created
a genuine conflict with the EPL-1.0 runtime it ships.
