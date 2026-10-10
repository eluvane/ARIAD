# Contributing to Ariad

## Contribution terms

Contributions to Ariad are governed by the [Mother of Licenses 1.0](LICENSE), including the upstream workflow in Section 6, the contribution terms in Section 9, and the patent terms in Section 10. Read these terms before submitting work.

Submit changes to the official [eluvane/ariad repository](https://github.com/eluvane/ariad). Technical forks, review branches, patches, and temporary test artifacts are permitted for bona fide upstream review under Section 6. Identify their contribution-only purpose and the official upstream project; do not publish them as general-use releases or an independent product. Private modifications may continue under Section 3 after the contribution process ends.

Contributors retain ownership of their original work. Section 9 grants the licensor, Eluvane, broad, irrevocable, royalty-free copyright permissions, including commercial use, sublicensing, transfer, and relicensing. Section 10 governs patent permissions. These grants do not entitle contributors to payment or revenue sharing unless separately agreed in writing or required by applicable law.

By knowingly submitting a Contribution with notice of Section 9, you accept its contribution terms. Contribution and patent grants remain governed by Sections 9 and 10. The default workflow does not require a separate acceptance statement or checkbox in the pull request or an accompanying message.

Submit only material you own or are authorized to contribute. Identify known third-party material and its license terms in the submission. Material you cannot license under these terms requires a separate arrangement with the licensor before incorporation.

For licensing questions or a separate agreement, contact [keiko1337@proton.me](mailto:keiko1337@proton.me).

## Development setup and checks

Work from a source checkout with the Rust toolchain in
[rust-toolchain.toml](rust-toolchain.toml), and the target's linker and C build tools.
The workspace declares its MSRV as `rust-version` in [Cargo.toml](Cargo.toml).
Run commands from the repository root.

The [CI workflow](.github/workflows/ci.yml) runs formatting, TOML checks, Clippy,
dependency checks, workspace tests, H2 tests, and the local H2 example.
[Quality-tool configuration](.config/ariad/README.md) lists the commands and
prerequisites. Use the checks relevant to the changed code and report any failed
or unrun check that limits confidence in the change.

For TLS or transport changes, use the matching feature tests.

Keep shared rules in one definition and use it from each caller. Reuse policy
limits and validators rather than copying their values or checks. The C header
defines the native ABI; core version constants define the wire versions. Follow
the [ABI generation procedure](crates/ffi/README.md#abi-definitions) when changing
these definitions. Document a shared contract at its definition and link to it
from callers. Keep separate rules when their error order or meaning differs.

Native features pin quiche, boring, boring-sys, and tokio-boring in the
[engine manifest](crates/engine/Cargo.toml). Before running a
native build, provide CMake **3.22 or later**, a target C/C++ compiler, and libclang
for bindings. Windows x86/x86_64 assembly builds also need NASM.

```sh
cargo test -p ariad-engine --features tls-rustls
cargo test -p ariad-engine --features h3-log-info
```

These commands work in POSIX shells and PowerShell. The
[manual native workflow](.github/workflows/native.yml) checks the
native and mixed TLS feature combinations. H3 requires the compile-time logging
policy described in the [README](README.md#integration-and-limits).

## Publish a release

Maintainers can publish native archives and generated release notes through the
manual [Release workflow](.github/workflows/release.yml).

## Open a pull request

Submit work to the official [eluvane/ariad repository](https://github.com/eluvane/ariad).
Keep each pull request focused on one concrete change. Exclude unrelated cleanup
and local build output. Update affected documentation and tests with the change.

### Title

Write a short title in English. Start with an action and name the affected behavior,
for example, `Reject OpenStream after session drain`. Keep the title aligned with
the final diff; avoid generic cleanup titles and broad completion claims.

### Description

Use compact English prose. Start with the problem and the resulting behavior.
One or two connected paragraphs usually suffice. Add a concrete trigger or
before-and-after example when it helps a reviewer understand the change.

Explain material compatibility, trust, resource, security, or performance effects.
For session, stream, or egress changes, identify the invariant being preserved.
State a missing or failed check briefly when it limits confidence. Keep detailed
commands and execution evidence in CI output or an accompanying work report.

Use prose without headings, bullet inventories, checklists, license-acceptance
statements, or boilerplate footers. Identify third-party material and its license
terms when applicable. Omit conversation history and abandoned approaches unless
they explain a relevant tradeoff.

### Labels

Use one primary `kind/*` label, the applicable `area/*` labels, and one `size/*`
label. The [repository label catalog](https://github.com/eluvane/ARIAD/labels)
defines their descriptions, colors, and size ranges. Count added and deleted
lines across the whole PR, including generated files and lockfiles. Update labels
when the final diff changes scope.

Add `risk/tcb` for trust-sensitive TLS, authorization, egress, or native memory
ownership changes. Use `risk/breaking-change` for maintainer-confirmed incompatibilities
that require migration guidance. `needs/*` and `status/blocked` identify missing
information, decisions, or blockers. Labels group generated release notes;
unmatched PRs remain in Other changes.

### Automated contributions

Coding agents follow the same title and description rules. Create branches and
pull requests only when requested. Preserve any supplied branch, title, and base;
merge only with an explicit maintainer instruction. Authorization to edit local
files does not authorize publishing a pull request.

## Markdown conventions

Write standalone documents for their intended readers. Describe current behavior
separately from proposals, and verify commands against the public API and manifests.
Keep task reports and private conversation context out of maintained documentation.

Use ATX headings, native `-` lists, labeled code fences, and repository-relative
links. Keep a blank line after headings and before lists, tables, and code blocks.
Pull request descriptions retain the prose-only format above.
