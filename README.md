# sonar-clojure

A SonarQube analyzer for Clojure. It claims `.clj`, `.cljs`, `.cljc`, `.edn` and
`.bb` so SonarQube indexes them, then supplies rules, measures, duplication,
highlighting, a symbol table, coverage and test results over them.

SonarQube ships no Clojure support. Without a language claiming these files,
nothing is indexed and no finding — from this plugin or any other source — can
attach to them.

**292 rules** · SonarQube 10.0+, verified on 26.7 Community · JRE 17+ · ~7 MB

---

## Install

```bash
cp sonar-clojure-plugin-0.1.0.jar $SONARQUBE_HOME/extensions/plugins/   # then restart
curl -s -u "$SONAR_TOKEN:" "$SONAR_URL/api/languages/list" | grep clj   # confirm
```

The confirm call needs a token — that endpoint is authenticated, and without
one it returns an empty body, which reads exactly like a failed install.

---

## Set up

Defaults work. Set a property only if your build writes elsewhere.

**Rules and navigation** — required.

```bash
clj-kondo --lint src test --config '{:output {:format :json}}' > target/clj-kondo.json
clj-kondo --lint src test --config '{:output {:format :json :analysis {:locals true :keywords true}}}' \
  > target/clj-kondo-analysis.json
```
```properties
sonar.clojure.kondo.reportPaths=target/clj-kondo.json
sonar.clojure.kondo.analysisPaths=target/clj-kondo-analysis.json
```

**Coverage** — use `--codecov`, not `--lcov`. cloverage's lcov writer reports a
partially covered line as fully covered; measured here, that overstated 22 of
451 lines.

cloverage is not a tool you have; add an alias for it.

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

**Security hooks** — required for 10 of the rules.

Ten rules are clj-kondo hooks rather than plugin code, because they need the
*resolved* var: `next.jdbc/execute!` is a SQL sink, a local function named
`query` is not. They ship in `clj-kondo/` and are installed by copying, which
also makes them fire in your editor and at the REPL rather than only at merge.

```bash
cp -r clj-kondo/. your-project/.clj-kondo/    # merge, do not overwrite
```

Without this the plugin still works; `weak-hash-algorithm`, `cipher-ecb-mode`,
`weak-cipher-algorithm`, `weak-tls-protocol`, `insecure-random`,
`eval-of-dynamic-value`, `read-string-untrusted`, `shell-command-injection`,
`sql-string-built` and `reflective-call` simply never fire.

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
  linter files under a catch-all rather than disappearing. 34 hand-written for
  what clj-kondo does not cover: JDK misuse (crypto, TLS, deserialization,
  JNDI, XXE, certificate validation), injection, credential exposure, ReDoS,
  `clojure.test` quality, and the concurrency hazards immutability does not
  remove. Each carries its CWE and OWASP category, checked against MITRE v4.20.
  Ten of the 34 are clj-kondo hooks (see **Security hooks** above); the rest
  are plugin-side, because they match a shape with no call to key on — a
  `reify` of `X509TrustManager`, a credential-shaped `def`, a regex literal.
- **Project vocabulary** — `banned-term` enforces CLAUDE.md's `Banned → use`
  table over every keyword clj-kondo resolves. Deliberately narrower than the
  full table: `:err` is `clojure.java.shell/sh`'s return key, and a rule
  demanding you rename another library's contract gets switched off.
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
  does not track argument positions.
- **No semantic model** in the plugin itself. Hook-detected rules get
  clj-kondo's resolution; plugin-side rules get a concrete syntax tree plus
  the analysis report, with no type inference.
- **Hooks cannot see their surroundings.** `callstack` gives the enclosing call
  *symbols*, already macroexpanded, not their nodes — measured — so a rule
  needing sibling forms (the XXE hardening check) cannot move to a hook.
- **`ns-analysis` is a signature index, not a call graph** — measured: var
  definitions only, no usages or positions. Interprocedural taint therefore
  runs plugin-side over the analysis report, and over-approximates.
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
clojure -M:test          # 81 tests, 253 assertions
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
