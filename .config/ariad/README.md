# Quality-tool configuration and checks

Tool configuration lives in `.config/ariad/`. The root Cargo manifests,
[`.editorconfig`](../../.editorconfig), and
[`.cargo/config.toml`](../../.cargo/config.toml) define workspace settings.
`.cargo/config.toml` sets `CLIPPY_CONF_DIR`.

| Directory | Tools |
| --- | --- |
| `build/` | Clippy |
| `formatters/` | rustfmt, Taplo, clang-format |
| `lints/` | Ruff, mypy, golangci-lint, clang-tidy, SwiftLint, markdownlint, yamllint |
| `security/` | cargo-deny, gitleaks, OSV Scanner, Semgrep |

## CI checks

Run each command from the repository root. The syntax works in POSIX shells and
PowerShell. Install the Rust toolchain and components in
[`rust-toolchain.toml`](../../rust-toolchain.toml), plus the `taplo`,
`cargo-machete`, and `cargo-deny` CLIs. Cargo checks may compile the workspace and
fetch dependencies. A first build needs network access and the target's build tools.

```sh
cargo fmt --all -- --check --config-path .config/ariad/formatters/rustfmt.toml
taplo fmt --check --config .config/ariad/formatters/taplo.toml
taplo lint --config .config/ariad/formatters/taplo.toml
cargo clippy --workspace --locked --all-targets -- -D warnings
cargo machete --with-metadata
cargo deny --config .config/ariad/security/cargo-deny.toml check
cargo test --workspace --locked
cargo run -p ariad-h2-connect --locked --offline
```

The [CI workflow](../../.github/workflows/ci.yml) defines these checks. A successful
command exits with code 0. Formatting commands with `--check` report differences
without rewriting files. The H2 example checks a local exchange and engine shutdown.
`--offline` requires dependencies to be present in the Cargo cache.

Separate CI jobs disable default features and check the engine with no transport,
with `h2`, and with `tls-rustls`. The minimum-version job checks only the core and
engine libraries at the workspace's declared `rust-version` in
[`Cargo.toml`](../../Cargo.toml), with default features disabled. The Linux C
consumer job builds the FFI shared library, links the C11 consumer with pthreads,
and runs it against local TLS, H2, and UDP fixtures.

The [manual native workflow](../../.github/workflows/native.yml) checks native
TLS/H3 separately. It covers `tls-boring`, `h3`, `h3-log-info`, and a mixed
Rustls/H3 configuration, with default features disabled for each selected set.
A workflow definition describes intended coverage; it does not establish a
successful result.

## Binding checks

The [Lint workflow](../../.github/workflows/lint.yml) checks the Python, Go,
C, C++, and Swift sources on every push and pull request. Its jobs do not build
Rust or link the native library. Every finding from an enabled rule fails its
job. Formatting differences also fail. No baseline or new-issues filter hides
existing findings.

| Language | Tools | Version pins | Failure policy |
| --- | --- | --- | --- |
| Python | Ruff and mypy | [Python requirements](lints/python-requirements.txt) | Ruff checks and format check; mypy strict mode |
| Go | golangci-lint and gofmt | [Lint workflow](../../.github/workflows/lint.yml) | Every issue fails; no output limits or default exclusions |
| C and C++ | clang-tidy, Cppcheck, clang-format | [Native requirements](lints/native-requirements.txt) | Warnings as errors; exhaustive Cppcheck data flow |
| Swift | SwiftLint static Linux build | [Lint workflow](../../.github/workflows/lint.yml) | `lint --strict`; archive checksum verified |

The Cppcheck wheel package and its bundled binary use different version numbers.
The native requirements pin the wheel package. Install Python and native packages
in a virtual environment. They are development tools, not binding dependencies.
The Python binding still needs only the standard library. The Go module's minimum
version is declared in [`go.mod`](../../bindings/go/go.mod); the workflow's Go
version is the analysis toolchain.

```sh
python -m pip install --only-binary=:all: -r .config/ariad/lints/python-requirements.txt
python -m pip install --only-binary=:all: -r .config/ariad/lints/native-requirements.txt
ruff check --config .config/ariad/lints/ruff.toml bindings/python tools
ruff format --check --config .config/ariad/lints/ruff.toml bindings/python tools
mypy --config-file .config/ariad/lints/mypy.ini
python -B -m unittest discover -s bindings/python -p 'test_*.py'
python -B tools/generate_abi.py --check
python -B -m unittest discover -s tools -p 'test_*.py'
clang-format --dry-run --Werror --style=file:.config/ariad/formatters/clang-format.yml crates/ffi/include/ariad.h crates/ffi/include/ariad.hpp crates/ffi/tests/consumer.c bindings/mobile/android/ariad_metadata_jni.c bindings/mobile/apple/ariad_module.h bindings/mobile/apple/Ariad-Bridging-Header.h
swiftlint-static lint --strict --config .config/ariad/lints/swiftlint.yml bindings/mobile/apple
```

Run Go checks from `bindings/go`, with `CGO_ENABLED=1` and `CGO_CPPFLAGS` pointing
to the absolute `crates/ffi/include` directory. A C compiler is required.
`gofmt -l .` must produce no paths; the workflow explicitly fails otherwise.

```sh
golangci-lint config verify --config ../../.config/ariad/lints/golangci.yml
golangci-lint run --config ../../.config/ariad/lints/golangci.yml --issues-exit-code=1
```

Native analysis uses C11 and C++17, real platform headers, and
`-Wall -Wextra -Wpedantic -Werror`. clang-tidy uses
[`clang-tidy.yml`](lints/clang-tidy.yml) with `WarningsAsErrors: '*'`.
Cppcheck enables warning, style, performance, and portability checks with
`--check-level=exhaustive --error-exitcode=1`. The workflow lists complete commands
for the C consumer, the C++ header, the JNI adapter, and the Apple C headers.
JNI analysis needs JDK headers. These checks do not prove native linkage,
network behavior, or mobile packaging.

The configured rule sets cover correctness, security, ownership, performance,
types, and consistent formatting. They avoid incompatible language conventions.
The following exceptions are part of that policy:

- Ruff does not require `typing_extensions`; Python 3.10 annotations stay in
  the standard library. It does not enforce pytest conventions on unittest tests
  or require a docstring for every method.
- gocritic's `dupImport` and `uncheckedInlineErr` are disabled. cgo adds a second
  `unsafe` import and rewrites source positions; these checks report generated
  imports and identifiers that do not exist in the source. Other Go analyzers
  remain enabled. The echo CLI's file open has one `#nosec G304 G703` directive:
  the local host deliberately chooses its own trust-root path.
- clang-tidy keeps C declarations, typedefs, and preprocessor constants in the
  public C header. It permits the standard `_POSIX_C_SOURCE` feature macro.
  `misc-include-cleaner` is disabled because SDK umbrella headers supply public
  declarations. The Annex K checker is disabled because these platforms do not
  share Annex K's optional `_s` functions. Buffer and format checks remain enabled.
- SwiftLint uses its static build without SourceKit. `statement_position`, which
  needs SourceKit, is disabled. SourceKit-only opt-in rules and compiler analyzer
  rules are not enabled. SwiftLint checks source syntax; it does not type-check
  the Swift-to-C integration.

## Additional checks

Install the corresponding CLI before running each command. The Markdown check
requires Node.js, npm, and `markdownlint-cli2`. If the package is not installed,
`npx` may offer to download it from npm. These commands are outside the main
CI workflow:

```sh
gitleaks detect --no-git --source . --config .config/ariad/security/gitleaks.toml --redact
semgrep scan --config .config/ariad/security/semgrep.yml --error --no-git-ignore .
yamllint -c .config/ariad/lints/yamllint.yml .github
npx markdownlint-cli2 --config .config/ariad/lints/markdownlint-cli2.jsonc
osv-scanner scan source --config .config/ariad/security/osv-scanner.toml -r .
```

Gitleaks scans for secrets, Semgrep applies configured rules, yamllint checks YAML,
markdownlint checks Markdown, and OSV Scanner checks dependencies against its
advisory data. Some scanners use network sources. A passing scan establishes only
what its configured rules and available data cover.
