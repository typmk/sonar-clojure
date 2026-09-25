# sonar-clojure

Clojure support for SonarQube: rules, security findings, measures, coverage,
test results and duplication for `.clj` `.cljs` `.cljc` `.edn` `.bb`.

SonarQube 25.2+ · JRE 17+ · EPL-2.0

## Install

Download the jar and its `.sha256` from the
[latest release](https://github.com/typmk/sonar-clojure/releases/latest), then:

```bash
sha256sum -c sonar-clojure-plugin-*.jar.sha256
cp sonar-clojure-plugin-*.jar $SONARQUBE_HOME/extensions/plugins/
# restart SonarQube, then confirm (needs a token: without one the reply is empty)
curl -s -u "$SONAR_TOKEN:" "$SONAR_URL/api/languages/list" | grep clj
```

This replaces [fsantiag/sonar-clojure](https://github.com/fsantiag/sonar-clojure),
which uses the same plugin key: remove its jar first.

## Analyse a project

With [clj-kondo](https://github.com/clj-kondo/clj-kondo/blob/master/doc/install.md) on `PATH`:

```bash
clojure -Ttools install-latest :lib io.github.typmk/sonar-clojure :as sonar-clojure   # once
clojure -Tsonar-clojure prepare     # installs the hooks, lints, lists missing reports
sonar-scanner
```

`prepare` lints `src` and `test`; pass `:lint '["src" "dev"]'` for other paths.
No property is needed while reports sit at these defaults:

| Report | Default path | Property to move it | Without it |
|---|---|---|---|
| clj-kondo findings + analysis | `target/clj-kondo.json` | `sonar.clojure.kondo.reportPaths`, `.analysisPaths` | no findings, no symbol navigation |
| cloverage (`--codecov`) | `target/coverage/codecov.json` | `sonar.clojure.cloverage.reportPaths` | coverage reads 0% |
| kaocha JUnit | `target/junit.xml` | `sonar.clojure.kaocha.reportPaths` | no test counts |

A missing report is not silent: the project gets an `incomplete-analysis` issue
naming it, and the `clj_analysis_completeness` metric, which a quality gate can
require at 100%.

<details>
<summary>deps.edn aliases for coverage and tests</summary>

```clojure
{:aliases
 {:coverage {:extra-paths ["test"]
             :extra-deps {cloverage/cloverage {:mvn/version "1.2.4"}}
             :main-opts ["-m" "cloverage.coverage" "--codecov" "-p" "src" "-s" "test"]}
  :test {:extra-paths ["test"]
         :extra-deps {lambdaisland/kaocha {:mvn/version "1.91.1392"}
                      lambdaisland/kaocha-junit-xml {:mvn/version "1.17.101"}}
         :main-opts ["-m" "kaocha.runner" "--plugin" "kaocha.plugin/junit-xml"
                     "--junit-xml-file" "target/junit.xml"]}}}
```

Use `--codecov`, not `--lcov`: cloverage's lcov writer counts a partly covered
line as covered.
</details>

<details>
<summary>Without prepare</summary>

```bash
mkdir -p .clj-kondo/imports/net.typemark
cp -r <sonar-clojure>/resources/clj-kondo.exports/net.typemark/sonar-clojure \
      .clj-kondo/imports/net.typemark/
clj-kondo --lint src test \
  --config '{:output {:format :json} :analysis {:locals true :keywords true}}' \
  > target/clj-kondo.json
```

The ten security rules that need resolved vars (SQL, shell, eval, crypto, TLS,
reflection) are clj-kondo hooks, so they also fire in your editor. Without the
hooks installed they never fire.
</details>

## Optional: more analyzers

Each imports as external issues when its property is set:

```properties
sonar.clojure.opengrep.reportPaths=target/opengrep.sarif
sonar.clojure.splint.reportPaths=…     sonar.clojure.eastwood.reportPaths=…
sonar.clojure.cljholmes.reportPaths=…  sonar.clojure.nvd.reportPaths=…
```

For dataflow taint (SQL, command and code injection, XSS, path traversal, SSRF):

```bash
opengrep scan --taint-intrafile -f opengrep/clojure-taint.yml \
  --sarif-output=target/opengrep.sarif src
```

Keep `--taint-intrafile` (without it a handler passing input to a helper is
missed) and a relative `-f` path (an absolute one leaks into the rule key).
Scores for each engine are in [corpus/README.md](corpus/README.md).

## What it checks

- **clj-kondo's linters** and **[sift](https://github.com/typmk/sift)'s rules**,
  generated from each tool's own registry and active where the tool defaults
  them on.
- **Security** — JDK crypto/TLS/deserialization misuse, injection, credential
  exposure, ReDoS, concurrency hazards; each with its CWE and OWASP category.
- **Measures** — size, cyclomatic and cognitive complexity, duplication,
  highlighting, symbol table.

## Limitations

- In-plugin taint follows one form and the call graph, without argument
  positions; opengrep is intra-file. Neither sees a flow across namespaces.
- No type inference.
- SonarQube 24.12 and 25.1 start but cannot load the plugin in the Compute
  Engine (the log shows one `sonar-clojure:` line instead of two).

## Development

```bash
clojure -X:gen-rules     # regenerate rule catalogues from clj-kondo and sift
clojure -T:build uber    # target/sonar-clojure-plugin-<version>.jar + .sha256
clojure -M:test          # reads the AOT classes, so build first
clojure -M:corpus        # score the engines against corpus/
```

CI runs these plus a real scan on each supported SonarQube. A `v<version>` tag
publishes a release. Arm the pre-commit hook with
`git config core.hooksPath .githooks`.

## Licence

[EPL-2.0](LICENSE); attributions in [NOTICE](NOTICE).
