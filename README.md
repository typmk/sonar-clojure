# sonar-clojure

A SonarQube analyzer for Clojure. It claims `.clj`, `.cljs`, `.cljc`, `.edn` and
`.bb` so SonarQube indexes them, then supplies rules, measures, duplication,
highlighting, a symbol table, coverage and test results over them.

SonarQube ships no Clojure support. Without a language claiming these files,
nothing is indexed and no finding — from this plugin or any other source — can
attach to them.

**293 rules** · SonarQube 25.2+, verified on 25.2 / 26.1 / 26.7 Community · JRE 17+ · ~7 MB

---

## Install

```bash
sha256sum -c sonar-clojure-plugin-0.1.1.jar.sha256                      # verify
cp sonar-clojure-plugin-0.1.1.jar $SONARQUBE_HOME/extensions/plugins/   # then restart
curl -s -u "$SONAR_TOKEN:" "$SONAR_URL/api/languages/list" | grep clj   # confirm
```

The confirm call needs a token — that endpoint is authenticated, and without
one it returns an empty body, which reads exactly like a failed install.

SonarQube does not verify a plugin dropped into `extensions/plugins`, so the
checksum is the integrity check, not a formality. A release also carries a
detached `.asc` when it was signed; verify it with
`gpg --verify sonar-clojure-plugin-0.1.1.jar.asc`.

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
both the local gate and the dashboard use that output.

**A missing report is data, not silence.** SonarQube has no native notion of an
incomplete analysis: a project nobody measured and a project that is clean
produce the same green dashboard. So the plugin publishes
`clj_analysis_completeness`, the percentage of the four reports above that were
present, and raises `incomplete-analysis` on the project naming each missing
input and what its absence costs. Add a quality-gate condition on the metric to
make an unmeasured analysis fail rather than merely inform.

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
  The CWE claims are checked in CI, not by review: MITRE's catalogue ships in
  the jar, and every mapping must be one MITRE's own `Mapping Notes / Usage`
  field marks `Allowed` or `Allowed-with-Review`. That check caught three
  `Discouraged` Class-level mappings (CWE-20, CWE-269, CWE-610) and one
  security rule asserting no CWE at all.
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
- **Its own inputs** — `clj_analysis_completeness` and `incomplete-analysis`,
  above.

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
- **SonarQube 25.2 and later.** Every 25.x and 26.x release from 25.1 to 26.7
  was installed and started; 25.2 is the oldest that works, and the boundary
  is exact rather than assumed. Below it:
  - **24.12 and 25.1 are broken** — their Compute Engine runs under a
    SecurityManager that denies `getClassLoader`, which is the classloader
    swap the Clojure bootstrap cannot work without. The web server starts and
    reports `UP` while the Compute Engine is already dead, so a health check
    does not catch it; the tell is that only one `sonar-clojure:` line reaches
    the log instead of two. SonarQube stopped running the CE under a
    SecurityManager in 25.2.
  - **10.7 and earlier are refused** by the manifest's `Sonar-Version: 10.13`,
    which is the plugin API version that introduced
    `PropertyDefinition$ConfigScope`. The floor previously read `10.0`; that
    did not make the plugin work on 10.7, it made SonarQube accept a plugin
    that then died with `ClassNotFoundException` and took the server down.
- SonarSource's taint engine is closed to third-party plugins, and Java's
  `javasecurity` rules are Developer Edition. Nothing here substitutes for them.

---

## Provenance

Two of this artifact's claims are about the outside world: that its generated
rules match a particular clj-kondo, and that its CWE mappings were validated
against a particular MITRE revision.

Only the clj-kondo version is *stored* — it exists solely at generation time,
when neither the library nor `deps.edn` is reachable from the plugin. The rule
count is a count of the shipped rules and the CWE revision is a field of the
shipped catalogue, so both are read from the artifacts they describe rather
than copied. A stored copy is a thing that can drift; a derived one is not.

The result is asserted by the test suite against `deps.edn`, printed to
`sonar.log` at plugin load, and shown in SonarQube's Marketplace page as the
plugin description:

```
136 rules generated from clj-kondo 2026.07.24; CWE mappings checked against
MITRE CWE v4.20 (2026-04-30)
```

Upgrading clj-kondo without re-running `clojure -X:gen-rules` fails the suite
rather than diverging quietly.

---

## Build

CI runs all of this on every push, plus a real scan against each supported
SonarQube in `.github/workflows/integration.yml` — that matrix is what found
both compatibility failures above, neither of which any unit test can reach.

```bash
clojure -X:gen-rules     # regenerate the rule catalogue from clj-kondo
clojure -T:build uber    # -> target/sonar-clojure-plugin-0.1.1.jar + .sha256
clojure -M:test          # 123 tests, 438 assertions (needs the jar)
clojure -T:build release # the same, gated on a clean tree and a v<version> tag
clojure -M:coverage      # 91% forms / 92% lines, measured
```

Arm the pre-commit hook in a fresh clone with
`git config core.hooksPath .githooks`. It lints staged Clojure files and
refuses the commit if it cannot find clj-kondo, because an unchecked commit is
not a passing one.

`uber` builds from whatever is on disk, which is right for iterating and wrong
for anything handed to someone else — the manifest would name a commit that
does not contain the code in the jar. It stamps `Build-Status: dirty` when that
happens. `release` refuses it outright, requires an annotated `v<version>` tag
on HEAD, and GPG-signs the jar when `SONAR_CLOJURE_GPG_KEY` names a key. With
no key it says so rather than producing an unsigned release that reads as
signed.

Java packages are `au.com.heisenbergtech.*` (the reverse of
heisenbergtech.com.au). `org/sonar/l10n/…` is SonarSource's own path and is not
renamed with them — a test asserts both, because a package rename that misses
either produces a plugin SonarQube loads and silently ignores.

The entry point is Java and must stay so; `au.com.heisenbergtech.sonar.ClojurePluginBootstrap`
documents why. Resources are staged into `target/stage`, never `target/classes`
— the latter precedes `resources` on the test classpath, so a copy there makes
the suite validate the last build instead of the source. Rule metadata is edited in
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
