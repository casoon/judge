---
title: Rules
description: The 80 rules in judge's static rule registry, with their evidence class and whether they can gate a verdict.
order: 2
---

Every rule judge can report is documented in a static registry (`src/rule_registry.rs`), one entry
per rule id. A test keeps each entry's verdict effect consistent with the evidence class the
analyzer assigns. For any rule,

```sh
cargo judge explain-rule <rule-id>
```

prints its evidence class, preconditions, exclusions, the wording its findings may use, its
verdict effect and, where one exists, a curated example. It is a pure lookup: it never runs an
analysis and never exits with 1.

## Evidence classes

| Class | Meaning | How findings are worded |
| --- | --- | --- |
| derived fact | An exact fact of the declared inputs, such as a syntax or manifest occurrence | As a fact of the input, never as a quality judgment |
| bounded semantic | A result within the examined workspace or view | "No reference found within the examined view", never an absolute "unused" |
| external measurement | The result of an imported report or a lookup at the time it ran | Valid for that snapshot, not a timeless truth |
| heuristic | A hint or possible reading | Never as proof; advisory by default |

## Verdict effect

**Gating** rules can fail a baseline verdict (exit code 1) and count towards the health score.
**Advisory only** rules are listed separately as advisory heuristics and never change the verdict,
the exit code or the score. 51 rules are gating and 29 are advisory only.

Many rules only run under preconditions: some need `judge.toml` configuration, the Deep Tier
(`--features deep`), a specific subcommand, an imported report or the `network` feature.
`explain-rule` states the precondition of each rule.

## Rule levels

A workspace can change the effect of any rule in `judge.toml`, one table per rule id:

```toml
[rules.generic-naming]
level = "off"

[rules.silent-default]
level = "gating"

[rules.catch-all-error]
level = "advisory"
allow-anyhow-at-boundary = true
```

| Level | Effect |
| --- | --- |
| `off` | The rule's findings are dropped before the verdict. Where a rule runs on its own (for example `duplicate-code` in the combined run), it is not run at all. Dropped findings are not counted as suppressions. |
| `advisory` | Findings are listed as advisory and never change the verdict, the exit code or the score. |
| `gating` | Findings can fail a baseline verdict and count towards the score. |

The finding itself (id, evidence class, location, evidence) stays the same; in JSON it gains a
`rule_level` field. Rule-specific keys such as `allow-anyhow-at-boundary` live in the same table.
An unknown rule id, an unknown level or an unknown key is a configuration error: judge exits with
2 before any analysis runs.

Every report names the active overrides, so a relaxed verdict is never silent: a
`rule overrides: …` line in the TTY and Markdown header, `rule_overrides` in JSON, and
`invocations[].ruleConfigurationOverrides` in SARIF. `cargo judge explain-rule <id>` shows the
effective level when `judge.toml` changes it, and `cargo judge init` writes a commented example.
Levels apply to the whole workspace; there are no per-path or per-crate levels.

## All rules

| Rule | Evidence class | Verdict effect |
| --- | --- | --- |
| `undocumented-public-item` | derived fact | gating |
| `semver-hazard` | derived fact | gating |
| `crate-boundary-violation` | bounded semantic | gating |
| `dependency-cycle` | bounded semantic | gating |
| `feature-graph-cycle` | derived fact | gating |
| `module-boundary-violation` | bounded semantic | gating |
| `internal-leak` | bounded semantic | gating |
| `module-boundary-violation-deep` | bounded semantic | gating |
| `re-export-chain` | heuristic | advisory only |
| `signature-complexity` | heuristic | advisory only |
| `maintainability-index` | heuristic | advisory only |
| `untested-hotspot` | external measurement | gating |
| `mutation-survivor` | external measurement | gating |
| `unused-pub-workspace` | bounded semantic | gating |
| `unused-pub-api` | heuristic | advisory only |
| `dead-enum-variant` | bounded semantic | gating |
| `test-only-pub` | bounded semantic | gating |
| `unreachable-from-entry` | bounded semantic | gating |
| `crate-coupling` | heuristic | advisory only |
| `module-coupling` | heuristic | advisory only |
| `feature-gated-dead-code` | heuristic | advisory only |
| `dead-trait-impl` | bounded semantic | gating |
| `duplicate-crate-versions` | derived fact | gating |
| `msrv-drift` | derived fact | gating |
| `workspace-dep-drift` | derived fact | gating |
| `release-profile-hazard` | derived fact | gating |
| `panic-strategy-conflict` | derived fact | gating |
| `misplaced-dependency-kind` | heuristic | advisory only |
| `unused-dev-dependency` | bounded semantic | gating |
| `heavy-dependency` | heuristic | advisory only |
| `unused-feature-flag` | derived fact | gating |
| `default-features-unused` | derived fact | gating |
| `unused-feature` | derived fact | gating |
| `unused-dependency` | bounded semantic | gating |
| `dep-without-repo` | derived fact | gating |
| `duplicate-code` | derived fact | gating |
| `size-distribution` | heuristic | advisory only |
| `complexity-concentration` | heuristic | advisory only |
| `unlinked-file` | bounded semantic | gating |
| `orphan-module` | bounded semantic | gating |
| `stringly-error-boundary` | heuristic | advisory only |
| `primitive-domain-value` | heuristic | advisory only |
| `boolean-state-cluster` | heuristic | advisory only |
| `public-invariant-bypass` | heuristic | advisory only |
| `manual-resource-lifecycle` | heuristic | advisory only |
| `unsafe-surface` | derived fact | gating |
| `unsafe-density` | heuristic | advisory only |
| `integer-cast-risk` | heuristic | advisory only |
| `panic-in-lib` | derived fact | gating |
| `hardcoded-secret` | heuristic | advisory only |
| `swallowed-result` | derived fact | gating |
| `empty-error-arm` | derived fact | gating |
| `catch-all-error` | derived fact | gating |
| `suppression-debt` | derived fact | gating |
| `merged-stub` | derived fact | gating |
| `empty-impl` | derived fact | gating |
| `assertion-free-test` | derived fact | gating |
| `tautological-test` | derived fact | gating |
| `ignored-test-accumulation` | derived fact | gating |
| `conversational-artifact` | derived fact | gating |
| `restating-comment` | derived fact | gating |
| `step-comment-inflation` | derived fact | gating |
| `generic-naming` | derived fact | gating |
| `doc-restates-signature` | derived fact | gating |
| `silent-default` | heuristic | advisory only |
| `context-free-propagation` | heuristic | advisory only |
| `debug-format-leak` | heuristic | advisory only |
| `complexity-inflation` | heuristic | advisory only |
| `abstraction-inflation` | heuristic | advisory only |
| `fragile-substring-classification` | heuristic | advisory only |
| `duplicative-reinvention` | heuristic | advisory only |
| `connectivity-drop` | heuristic | advisory only |
| `monomorphization-load` | heuristic | advisory only |
| `name-collision-risk` | heuristic | advisory only |
| `phantom-crate` | external measurement | gating |
| `phantom-version` | external measurement | gating |
| `fresh-low-reputation-dep` | external measurement | gating |
| `yanked-dependency` | external measurement | gating |
| `dep-single-maintainer` | external measurement | gating |
| `known-vulnerability` | external measurement | gating |

## Release profile

`release-profile-hazard` and `panic-strategy-conflict` read the effective release profile of
workspaces with at least one `bin` target. `cargo judge inspect` prints the same resolution.

- Sources: the workspace root `Cargo.toml` and the workspace root `.cargo/config.toml`. A value
  in the config file overrides the manifest value for the same key, as in Cargo. A custom
  profile follows its `inherits` chain.
- Deliberately ignored: the user's home config (`~/.cargo/config.toml`), config files above the
  workspace root and `CARGO_PROFILE_*` environment variables. The result is the same on every
  machine, but a build that sets any of them can use a different profile than judge reports.
- `release-profile-hazard` reports `opt-level = 0` and `debug-assertions = true`, at the manifest
  or config line that sets them.
- `panic-strategy-conflict` reports `panic = "abort"` when non-test code calls
  `std::panic::catch_unwind`, by path or import. Code under `#[cfg(test)]`, `#[test]` functions
  and `tests/`, `examples/`, `benches/` and `build.rs` do not count. The finding sits at the
  `panic` line and lists the call sites in its evidence.
- `[profile.release.package.*]` overrides are listed by `inspect`, not judged. lto,
  codegen-units, strip and binary size are trade-offs, not hazards.
