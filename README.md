# sonar-clojure

A SonarQube analyzer for Clojure. It claims `.clj`, `.cljs`, `.cljc`, `.edn` and
`.bb` so SonarQube indexes them, then supplies rules, measures, duplication,
highlighting, a symbol table, coverage and test results over them.

SonarQube ships no Clojure support. Without a language claiming these files,
nothing is indexed and no finding — from this plugin or any other source — can
attach to them.

SonarQube 25.2+, verified on 25.2 / 26.1 / 26.7 Community · JRE 17+ · EPL-2.0

---

## Install

Download the jar and its `.sha256` from the
[latest release](https://github.com/typmk/sonar-clojure/releases/latest), then:

```bash
sha256sum -c sonar-clojure-plugin-*.jar.sha256                        # verify
cp sonar-clojure-plugin-*.jar $SONARQUBE_HOME/extensions/plugins/     # then restart
curl -s -u "$SONAR_TOKEN:" "$SONAR_URL/api/languages/list" | grep clj # confirm
```

SonarQube does not verify a plugin dropped into `extensions/plugins`, so the
checksum is the integrity check. A release signed with GPG carries a detached
`.asc` as well; a release without one was not signed.

The confirm call needs a token. Without one the endpoint returns an empty body,
which looks exactly like a failed install.

---

## Quick start

In the project to analyse, with [clj-kondo](https://github.com/clj-kondo/clj-kondo/blob/master/doc/install.md)
on `PATH`:

```bash
clojure -Ttools install-latest :lib io.github.typmk/sonar-clojure :as sonar-clojure   # once
clojure -Tsonar-clojure prepare
sonar-scanner
```

`prepare` installs the security hooks, lints once, writes
`target/clj-kondo.json`, and names each report still missing with the
command that produces it. It lints `src` and `test` by default; pass
`:lint '["src" "dev"]'` for other paths.

No `sonar.clojure.*` property is needed while reports sit at the default
paths below.

---

## Reports

The plugin reads reports and runs nothing itself, so CI lints and tests once
and both the local gate and the dashboard use that output.

| Report | Default path | Property | Without it |
|---|---|---|---|
| clj-kondo findings | `target/clj-kondo.json` | `sonar.clojure.kondo.reportPaths` | no rule findings at all |
| clj-kondo analysis | `target/clj-kondo.json` | `sonar.clojure.kondo.analysisPaths` | no symbol navigation, no interprocedural taint |
| cloverage coverage | `target/coverage/codecov.json` | `sonar.clojure.cloverage.reportPaths` | coverage reads as 0% |
| kaocha tests | `target/junit.xml` | `sonar.clojure.kaocha.reportPaths` | no test counts |

**clj-kondo** — one run writes the findings and the analysis together, and is
what `prepare` runs:

```bash
clj-kondo --lint src test \
  --config '{:output {:format :json} :analysis {:locals true :keywords true}}' \
  > target/clj-kondo.json
```

**Coverage** — use `--codecov`, not `--lcov`. cloverage's lcov writer reports a
partially covered line as fully covered; measured here, that overstated 22 of
451 lines.

```clojure
;; deps.edn
{:aliases {:coverage {:extra-paths ["test"]
                      :extra-deps {cloverage/cloverage {:mvn/version "1.2.4"}}
                      :main-opts ["-m" "cloverage.coverage" "--codecov"
                                  "-p" "src" "-s" "test"]}}}
```
```bash
clojure -M:coverage
```

**Tests** — kaocha with its JUnit plugin:

```clojure
;; deps.edn
{:aliases {:test {:extra-paths ["test"]
                  :extra-deps {lambdaisland/kaocha {:mvn/version "1.91.1392"}
                               lambdaisland/kaocha-junit-xml {:mvn/version "1.17.101"}}
                  :main-opts ["-m" "kaocha.runner"
                              "--plugin" "kaocha.plugin/junit-xml"
                              "--junit-xml-file" "target/junit.xml"]}}}
```

**A missing report is data, not silence.** SonarQube has no native notion of an
incomplete analysis: a project nobody measured and a project that is clean
produce the same green dashboard. The plugin publishes
`clj_analysis_completeness`, the percentage of the four inputs above that were
present, and raises `incomplete-analysis` on the project naming each missing
one and what its absence costs. A findings report written without `:analysis`
counts as the analysis missing. Add a quality-gate condition on the metric to
make an unmeasured analysis fail rather than merely inform.

---

## Security hooks

Ten rules are clj-kondo hooks rather than plugin code, because they need the
*resolved* var: `next.jdbc/execute!` is a SQL sink, a local function named
`query` is not. Being hooks, they also fire in your editor and at the REPL,
not only at merge.

`prepare` installs them. By hand, copy the export directory to where clj-kondo
loads it without `:config-paths`:

```bash
mkdir -p .clj-kondo/imports/net.typemark
cp -r <sonar-clojure>/resources/clj-kondo.exports/net.typemark/sonar-clojure \
      .clj-kondo/imports/net.typemark/
```

Their clj-kondo linter keys are `:typemark/<rule>` (`:typemark/sql-string-built`);
the Sonar rule key drops the namespace. Without the hooks the plugin still
works; `weak-hash-algorithm`, `cipher-ecb-mode`, `weak-cipher-algorithm`,
`weak-tls-protocol`, `insecure-random`, `eval-of-dynamic-value`,
`read-string-untrusted`, `shell-command-injection`, `sql-string-built` and
`reflective-call` never fire.

---

## Taint analysis (optional)

The plugin follows a value from a known source to a known sink within one
form, and across clj-kondo's call graph without argument positions. It is not
a dataflow engine. [opengrep](https://github.com/opengrep/opengrep) is, for
Clojure, within one file, and its findings import as external issues:

```bash
opengrep scan --taint-intrafile -f opengrep/clojure-taint.yml \
  --sarif-output=target/opengrep.sarif src
```
```properties
sonar.clojure.opengrep.reportPaths=target/opengrep.sarif
```

- **`--taint-intrafile` is required.** Without it opengrep propagates taint
  through return values only, and a handler passing user input into a
  database helper — the commonest real shape — produces nothing (measured).
- **Use a relative `-f` path.** opengrep derives the SARIF rule id from where
  its config was loaded, so an absolute path puts your home directory in the
  rule key.

`opengrep/clojure-taint.yml` ships six rules — SQL, command and code
injection, XSS, path traversal and SSRF — each carrying its CWE. The same flow
split across two namespaces is not found; cross-file analysis is Semgrep's
commercial engine, not this one. How the two engines score is in
[corpus/README.md](corpus/README.md).

---

## Other analyzers (optional)

Unset means not run. Each imports as external issues, from clj-kondo-shaped
JSON or SARIF (read by shape, so any SARIF-emitting tool works):

```properties
sonar.clojure.splint.reportPaths=…      sonar.clojure.eastwood.reportPaths=…
sonar.clojure.cljholmes.reportPaths=…   sonar.clojure.nvd.reportPaths=…
```

splint's rules are browsable in SonarQube before it has ever run.

File selection is keyed by language key, as `sonar.java.file.suffixes` is:

```properties
sonar.clj.file.suffixes=.clj,.cljs,.cljc,.edn,.bb
sonar.clj.file.patterns=**/*.clj,**/*.cljs,**/*.cljc,**/*.edn,**/*.bb
```

---

## What it analyses

- **clj-kondo's linters** — generated from clj-kondo's own configuration, so
  an upgrade adds rules mechanically and the two cannot drift. A finding from
  a newer linter files under a catch-all rather than disappearing. Active by
  default exactly where clj-kondo does not default to `:off`.
- **sift's rules** — [sift](https://github.com/typmk/sift) runs inside the
  plugin: correctness, suspicious code, performance, complexity, style, test
  quality and docstrings. Also generated, from sift's registry. Active by
  default exactly where a plain `sift lint` runs it, and a scan computes only
  the rules the quality profile has active.
- **Security** — JDK misuse (crypto, TLS, deserialization, JNDI, XXE,
  certificate validation), injection, credential exposure, ReDoS, and the
  concurrency hazards immutability does not remove. Each carries its CWE and
  OWASP category. The CWE claims are checked in CI against MITRE's catalogue,
  which ships in the jar: every mapping must be one MITRE's own `Mapping
  Notes / Usage` field marks `Allowed` or `Allowed-with-Review`.
- **Measures** — ncloc, comments, functions, classes, statements, cyclomatic
  and cognitive complexity, and the per-line data new-code coverage is
  computed from.
- **Also** — duplication (literals collapsed, so blocks differing only in
  constants still match), highlighting, and a symbol table from clj-kondo's
  analysis.

`unscoped-tenant-query`, `partial-match-validation` and
`ambiguous-owner-check` ship registered but **inactive**: the first two
because their precision does not yet justify switching them on for everyone,
and the tenancy rules because they need a tenant pattern SonarQube cannot
supply.

---

## Limitations

- **Taint tracking is not a taint engine.** No argument positions. For real
  dataflow, import opengrep — intra-file only.
- **No semantic model** in the plugin. Hook rules get clj-kondo's resolution;
  plugin-side rules get a concrete syntax tree plus the analysis report, with
  no type inference.
- **Hooks cannot see their surroundings.** `callstack` gives the enclosing
  call *symbols*, already macroexpanded, not their nodes — so a rule needing
  sibling forms (the XXE hardening check) cannot be a hook.
- **rewrite-clj is stricter than Clojure's reader** in rare cases. An
  unparseable file contributes no measures and raises an analysis error
  naming itself.
- **SonarQube 25.2 and later.** Every release from 25.1 to 26.7 was installed
  and started. 24.12 and 25.1 run the Compute Engine under a SecurityManager
  that denies the classloader swap the Clojure bootstrap needs; the web server
  still reports `UP`, and the tell is one `sonar-clojure:` log line instead of
  two. 10.7 and earlier are refused by the manifest's `Sonar-Version: 10.13`.
- SonarSource's taint engine is closed to third-party plugins, and Java's
  `javasecurity` rules are Developer Edition. Nothing here substitutes for them.

---

## Development

```bash
clojure -X:gen-rules     # regenerate the rule catalogues from clj-kondo and sift
clojure -T:build uber    # -> target/sonar-clojure-plugin-<version>.jar + .sha256
clojure -M:test          # needs the jar: the suite reads the AOT classes
clojure -M:coverage
clojure -M:corpus        # score the engines against corpus/, see corpus/README.md
```

CI runs all of it on every push, plus a real scan against each supported
SonarQube (`.github/workflows/integration.yml`). A `v<version>` tag builds with
`clojure -T:build release`, which refuses a dirty tree or a missing annotated
tag, and publishes the jar and its checksum as a GitHub release.

Arm the pre-commit hook in a fresh clone with
`git config core.hooksPath .githooks`. It lints staged files and refuses the
commit if it cannot find clj-kondo.

The clj-kondo version the catalogue was generated from is recorded in the jar
and printed at plugin load; upgrading clj-kondo without re-running
`clojure -X:gen-rules` fails the suite.

The entry point is Java and must stay so; `net.typemark.sonar.ClojurePluginBootstrap`
documents why. Rule metadata is edited in
`resources/org/sonar/l10n/clj/rules/clj-kondo/<key>.{json,html}` —
SonarSource's own layout — without recompiling.

---

## Licence

[Eclipse Public License 2.0](LICENSE). Attribution for redistributed components
in [NOTICE](NOTICE).

EPL because the jar shades the EPL-1.0 Clojure runtime: same licence family, no
compatibility question. `sonar-plugin-api` is LGPL-3.0 but is a provided
dependency — the jar carries no `org/sonar/api` classes — so no obligation
attaches.
