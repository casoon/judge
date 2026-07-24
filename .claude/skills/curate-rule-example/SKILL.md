---
name: curate-rule-example
description: Adds or improves a curated `RuleMetadata.example` entry in `src/rule_registry.rs` — the minimal triggering code snippet plus one-sentence rationale surfaced by `cargo judge explain-rule <id>`, intended for reuse outside judge itself (e.g. the project's future landing page). Use this whenever asked to add a rule example, make judge's examples more illustrative/convincing/realistic, or curate landing-page material for a rule — including casual phrasing like "make this example better" or "add an example for rule X".
---

# Curate a rule example

`RuleMetadata` (in `src/rule_registry.rs`) has an optional `example: Option<RuleExample>` field — a minimal, self-contained code snippet (`before`) plus a one-sentence, plain-language reason it matters (`why_it_matters`). This is the single source of truth for "what does judge actually catch" content: `cargo judge explain-rule <id>` (both `tty` and `--format json`) surfaces it, so a future landing page (or any other consumer) pulls from here instead of duplicating hand-written copy that can drift from what the tool really detects.

As of this skill's writing, only 3 of ~62 rules have a curated example (`swallowed-result`, `panic-in-lib`, `hardcoded-secret`) — this is an incremental rollout, not a one-shot backfill. `todo.md`'s "Infrastruktur & Vertrieb" section tracks the remaining count.

## The two failure modes this skill exists to prevent

1. **Unconvincing examples.** The fastest way to get an example is copying an existing unit test's fixture string verbatim. Don't — test fixtures use placeholder names (`f`, `x`, `some_call`) deliberately, to isolate the exact syntactic condition under test. That's correct for a test and wrong for a landing page: nobody looking at `fn f() { let _ = some_call(); }` thinks "that's my code." Use realistic call sites instead (`std::fs::write(path, data)`, `raw.unwrap()` on a named config value) — the detector is syntax-only and name-blind, so realism costs nothing functionally.
2. **A literal that trips a real secret scanner.** If the rule is at all secret/credential-shaped (`hardcoded-secret` and anything like it), never write a `before` string that byte-for-byte matches a real provider's secret format (AWS `AKIA` + 16 chars, Google `AIza` + 39 chars, GitHub `ghp_` + 36 chars, etc.) — GitHub's own secret scanning regex-matches the *committed file bytes*, not just what judge's detector sees, and will flag your own repo as leaking a secret (this happened once already — see the `f55899f` commit fixing `google_api_key`'s test fixture). Prefer the entropy lane's own safe shape instead: a suspiciously-named binding with a high-entropy string that uses characters (`$`, `#`, `@`, `^`, `&`, `!`) no real provider format uses, e.g. `"Kx7$mQ2#Lp9@Rn4^Wz6&Tb3!"`. If a rule's own canonical test already uses a provider-shaped literal, that test itself may need the same split-string treatment `f55899f` used — check before reusing it as an example source.

## Procedure

1. **Find the rule's registry entry.** `grep -n 'id: "<rule-id>"' src/rule_registry.rs`. Note which module owns the rule (the file comment header just above groups entries by source module, e.g. `-- security.rs --`).

2. **Find (or write) a minimal triggering case.** Look for that module's own positive test for the rule (`grep -n 'RULE_NAME_CONST' src/<module>.rs`, then find the `#[test] fn ..._is_flagged()` that asserts exactly one hit). Use it as a functional reference for what shape of code triggers the rule — but don't copy its literal string; write a fresh, realistic one that triggers the same code path. Keep it to a *single* triggering occurrence (one `.unwrap()`, one `let _ = ...;`) unless the rule's own finding-per-occurrence semantics don't matter for the drift-guard test below — multiple occurrences fan out into multiple findings and complicate a simple `assert_eq!(len(), 1)`.

3. **Write `why_it_matters`.** One sentence, plain language, for someone outside judge's own domain — the real-world consequence, not the syntax being matched. This is deliberately distinct from the registry's `allowed_wording` field, which constrains a *finding's own printed text* (must stay hedged/non-absolute per todo.md §17.4); `why_it_matters` is marketing/documentation copy and can be direct.

4. **Add the entry** (or edit the existing one) as `example: Some(RuleExample { before: "...", why_it_matters: "..." }),` in the matching `RuleMetadata` literal. If the rule's own shape needed the anti-secret-scanner precaution from above, leave a `//` comment explaining the deliberate choice (see the `hardcoded-secret` entry for the pattern).

5. **Add a drift-guard test** in the owning module's `#[cfg(test)] mod tests`, following this exact shape (adjust the rule constant/module path):

   ```rust
   /// The registry's curated `example.before` for this rule (see
   /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
   /// this is what keeps a landing-page-facing example from silently
   /// drifting away from what judge actually flags.
   #[test]
   fn <rule>_registry_example_still_triggers_the_rule() {
       let example = crate::rule_registry::lookup(<RULE_CONST>)
           .expect("<rule-id> has a registry entry")
           .example
           .expect("<rule-id> has a curated example")
           .before;
       let findings = findings_for(example, "<unique-fixture-name>");
       assert_eq!(rule_findings(&findings, <RULE_CONST>).len(), 1);
   }
   ```

   The test reads `example.before` **from the registry directly** — never copy the string into the test as a second literal. That's what makes drift structurally impossible: change the snippet in the registry and this test re-validates it automatically; change the detector enough to stop matching and this test fails, forcing a fix instead of a silently stale example.

6. **Validate, scoped to files you touched** — this repo has known pre-existing `rustfmt`-version drift in `src/coverage.rs`, `src/dead_code.rs`, `src/functions.rs` unrelated to this work; never run bare `cargo fmt --all` (it silently reformats those too) or stage/commit them.
   - `rustfmt --edition 2024 src/rule_registry.rs src/<module>.rs` (format only the files you edited)
   - `cargo test --lib -- registry_example` (fast sanity check on just the new/changed drift-guard tests), then a full `cargo test`
   - `cargo clippy --all-targets -- -D warnings`

7. **Spot-check the rendered output**: `cargo run --quiet --bin cargo-judge -- explain-rule <rule-id>` (tty) and `... --format json` — confirm the example reads naturally and the JSON shape is `{"before": "...", "why_it_matters": "..."}` under `"example"`. No other wiring is needed — `run_explain_rule` in `src/main.rs` already renders any `Some(RuleExample)` generically.

8. **Update `todo.md`'s rollout tracker** (the "Infrastruktur & Vertrieb" bullet about `RuleMetadata.example` coverage) — bump the count of rules covered, since that file is the project's own "what's still open" ledger, not this skill.

## What this skill does not cover

- Rules whose canonical trigger needs a multi-file workspace fixture or git history (e.g. `change-coupling-signal`, anything Deep-Tier-only like `unused-pub-workspace`) — those need a richer `before` representation than a single source string, which `RuleExample` doesn't model yet. Flag this as a gap rather than forcing a misleading single-file example.
- Deciding whether generated Markdown docs should exist for these examples — that's a separate, deliberately-deferred todo.md item (only worth doing once an actual external consumer needs Markdown instead of the existing `explain-rule --format json`).
