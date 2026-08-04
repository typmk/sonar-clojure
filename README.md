# sonar-clojure

A SonarQube analyzer for Clojure. It claims `.clj`, `.cljs`, `.cljc`, `.edn` and
`.bb` so SonarQube indexes them, then supplies rules, measures, duplication,
highlighting, a symbol table, coverage and test results over them.

SonarQube ships no Clojure support. Without a language claiming these files,
nothing is indexed and no finding — from this plugin or any other source — can
attach to them.

**291 rules** · SonarQube 10.0+, verified on 26.7 Community · JRE 17+ · ~7 MB

---

## Install

```bash
cp sonar-clojure-plugin-0.1.0.jar $SONARQUBE_HOME/extensions/plugins/   # then restart
curl -s "$SONAR_URL/api/languages/list" | grep clj                      # confirm
```

---

## Set up

Defaults work. Set a property only if your build writes elsewhere.

**Rules and navigation** — required.

```bash
clj-kondo --lint src test --config '{:output {:format :json}}' > target/clj-kondo.json
clj-kondo --lint src test --config '{:output {:format :json :analysis {:locals true}}}' \
  > target/clj-kondo-analysis.json
```
```properties
sonar.clojure.kondo.reportPaths=target/clj-kondo.json
sonar.clojure.kondo.analysisPaths=target/clj-kondo-analysis.json
```

**Coverage** — use `--codecov`, not `--lcov`. cloverage's lcov writer reports a
partially covered line as fully covered; measured here, that overstated 22 of
451 lines.

```bash
clojure -M:coverage --codecov -p src -s test
```
```properties
sonar.clojure.cloverage.reportPaths=target/coverage/codecov.json
```

**Tests** — via the `kaocha-junit-xml` plugin.

```bash
bin/kaocha --plugin kaocha.plugin/junit-xml --junit-xml-file target/junit.xml
```
```properties
sonar.clojure.kaocha.reportPaths=target/junit.xml
```

**Other analyzers** — optional; unset means not run.

```properties
sonar.clojure.splint.reportPaths=…      sonar.clojure.eastwood.reportPaths=…
sonar.clojure.cljholmes.reportPaths=…   sonar.clojure.nvd.reportPaths=…
```

**File selection** — keyed by language key, as `sonar.java.file.suffixes` is.

```properties
sonar.clj.file.suffixes=.clj,.cljs,.cljc,.edn,.bb
sonar.clj.file.patterns=**/*.clj,**/*.cljs,**/*.cljc,**/*.edn,**/*.bb
```

The plugin reads reports and invokes nothing, so CI lints and tests once and
both the local gate and the dashboard use that output. A missing report is
reported loudly, never treated as a clean result.

---

## What it analyses

- **Rules** — 136 generated from clj-kondo's own configuration, so an upgrade
  adds rules mechanically and the two cannot drift; a finding from a newer
  linter files under a catch-all rather than disappearing. 33 hand-written for
  what clj-kondo does not cover: JDK misuse (crypto, TLS, deserialization,
  JNDI, XXE, certificate validation), injection, credential exposure, ReDoS,
  `clojure.test` quality, and the concurrency hazards immutability does not
  remove. Each carries its CWE and OWASP category, checked against MITRE v4.20.
- **Measures** — ncloc, comments, functions, classes, statements, cyclomatic
  and cognitive complexity, and the per-line data new-code coverage is computed
  from. Where a coverage report exists the executable set comes from it.
- **Also** — duplication (literals collapsed, so blocks differing only in
  constants still match), highlighting, and a symbol table from clj-kondo's
  analysis.
- **External** — splint, clj-holmes, eastwood and nvd-clojure import as
  external issues; splint's 121 rules are browsable before it has ever run.

Two rules ship registered but **inactive** — `unscoped-tenant-query` and
`partial-match-validation` — because their precision does not yet justify
switching them on for everyone.

---

## Limitations

- **Taint tracking is not a taint engine.** It follows a value from a known
  source to a known sink within one form, and across clj-kondo's call graph. It
  does not track argument positions, so the interprocedural rule
  over-approximates and says so in its own description.
- **No semantic model.** A concrete syntax tree plus clj-kondo's analysis. No
  type inference; no resolution beyond what clj-kondo provides.
- **rewrite-clj is stricter than Clojure's reader** in rare cases. An unparseable
  file contributes no measures and raises an analysis error naming itself.
- **Verified on SonarQube 26.7 only.** The `Sonar-Version: 10.0` floor is a
  declaration, not a tested claim.
- SonarSource's taint engine is closed to third-party plugins, and Java's
  `javasecurity` rules are Developer Edition. Nothing here substitutes for them.

---

## Build

```bash
clojure -X:gen-rules     # regenerate the rule catalogue from clj-kondo
clojure -T:build uber    # -> target/sonar-clojure-plugin-0.1.0.jar
clojure -M:test          # 80 tests, 259 assertions
```

The entry point is Java and must stay so; `hbt.sonar.ClojurePluginBootstrap`
documents why. Rule metadata is edited in
`resources/org/sonar/l10n/clj/rules/clj-kondo/<key>.{json,html}` — SonarSource's
own layout — without recompiling.

---

## Licence

[Eclipse Public License 2.0](LICENSE). Attribution for redistributed components
in [NOTICE](NOTICE).

EPL because the jar shades the EPL-1.0 Clojure runtime: same licence family, no
compatibility question. `sonar-plugin-api` is LGPL-3.0 but is a provided
dependency — the jar carries no `org/sonar/api` classes — so no obligation
attaches.
