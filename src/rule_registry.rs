//! Static, versioned documentation for every rule id judge can emit (todo.md
//! §17.5: "Für jede Regel in der Registry Evidenzklasse, Voraussetzungen,
//! Ausschlussgründe, zulässige Formulierungen und Verdict-Effekt fest
//! hinterlegen"). This is a pure lookup table, not a detector — the text
//! here is consolidated from each rule's own module/function doc comments,
//! not invented, and is consulted by `cargo judge explain-rule <id>`.
//!
//! Every rule-id constant defined anywhere in this crate (`grep -rn 'pub
//! const.*_RULE\b.*: &str = "' src/*.rs`) has exactly one entry here,
//! including the three `crate::pattern` aggregation rules — those never
//! produce a `Finding` (see that module's doc comment) and so are always
//! `Heuristic`/[`VerdictEffect::AdvisoryOnly`] here, consistent with
//! [`crate::finding::evidence_class_for_rule`]'s fallback for any rule id it
//! doesn't recognize.

use crate::finding::EvidenceClass;

/// Whether a rule can affect a verdict/exit code or the health score.
/// Documentation-only mirror of [`EvidenceClass::is_gating`] — see the
/// consistency test below, which is the single place that keeps the two from
/// drifting apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictEffect {
    Gating,
    AdvisoryOnly,
}

impl VerdictEffect {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Gating => "gating",
            Self::AdvisoryOnly => "advisory_only",
        }
    }
}

/// One rule's fixed documentation: evidence class, when it runs, its known
/// limitations, the wording discipline its findings must follow (todo.md
/// §17.4), and whether it can gate a verdict.
#[derive(Debug, Clone, Copy)]
pub struct RuleMetadata {
    pub id: &'static str,
    pub evidence_class: EvidenceClass,
    /// When the rule is evaluated at all — e.g. "always evaluated", "opt-in
    /// via `--features deep`", "requires `judge.toml` config".
    pub preconditions: &'static str,
    /// Known exclusion reasons / scope limits (false-positive sources, scope
    /// boundaries) — taken from the rule's own module/function doc comments.
    /// `"none documented"` where no module doc calls out a limitation, so an
    /// empty entry is never mistaken for "nothing was checked".
    pub exclusions: &'static str,
    /// Wording this rule's findings are allowed to use (todo.md §17.4: never
    /// an absolute factual claim for a `heuristic`/`bounded_semantic` rule).
    pub allowed_wording: &'static str,
    pub verdict_effect: VerdictEffect,
}

const DERIVED_FACT_WORDING: &str = "State as an exact fact of the declared inputs (e.g. an occurrence count) — never as a quality judgment. The syntax/manifest fact is certain; whether it constitutes a real problem is not (todo.md §17.3).";

const BOUNDED_SEMANTIC_WORDING: &str = "State as 'no reference found within the examined workspace/view', scoped explicitly to what was searched — never as an absolute 'unused' or 'dead'; usage outside the examined view is not_inferable (todo.md §17.3, §17.4).";

const EXTERNAL_MEASUREMENT_WORDING: &str = "State as the result of the imported snapshot/lookup at the time it ran — valid for that snapshot, never a timeless truth; re-running later can change the result (todo.md §17.2).";

const HEURISTIC_WORDING: &str = "State as a hint or possible reading, never as proof — advisory by default, no exit code 1 (todo.md §17.2). Never phrase as an absolute claim about design correctness, authorship, or code quality (todo.md §17.4).";

/// The single authoritative documentation table — one entry per rule id
/// defined anywhere in this crate. See the module doc comment for the
/// completeness guarantee and the consistency test below for the
/// evidence-class/verdict-effect invariant.
pub const RULE_REGISTRY: &[RuleMetadata] = &[
    // -- boundaries.rs --------------------------------------------------
    RuleMetadata {
        id: "crate-boundary-violation",
        evidence_class: EvidenceClass::BoundedSemantic,
        preconditions: "Requires a `judge.toml` with `[[boundary]]`/`[layers]` config; opt-in — `cargo judge boundaries` (and the boundaries block of bare `cargo judge`/`audit`) does nothing without it.",
        exclusions: "Scoped to crate-level dependency edges only, fully knowable from `cargo_metadata` without a build; module-level boundaries need semantic module resolution the Fast Tier doesn't have yet.",
        allowed_wording: BOUNDED_SEMANTIC_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    RuleMetadata {
        id: "dependency-cycle",
        evidence_class: EvidenceClass::BoundedSemantic,
        preconditions: "Requires a `judge.toml` with `[[boundary]]`/`[layers]` config; opt-in — `cargo judge boundaries` (and the boundaries block of bare `cargo judge`/`audit`) does nothing without it.",
        exclusions: "Scoped to crate-level dependency edges only, fully knowable from `cargo_metadata` without a build; module-level cycles need semantic module resolution the Fast Tier doesn't have yet.",
        allowed_wording: BOUNDED_SEMANTIC_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    // -- coverage.rs ------------------------------------------------------
    RuleMetadata {
        id: "untested-hotspot",
        evidence_class: EvidenceClass::ExternalMeasurement,
        preconditions: "Requires `cargo judge coverage --lcov <path>` — an externally generated `cargo-llvm-cov` LCOV report; judge never measures coverage itself, only imports an already-generated snapshot.",
        exclusions: "Complexity and churn inputs are `derived_fact`/`heuristic` in isolation, but the imported coverage snapshot is the rarest, least locally-verifiable ingredient, so it sets the class for the combination.",
        allowed_wording: "State as the result of the imported coverage/complexity/churn snapshot — never a timeless truth. Complexity/churn inputs alone would only be heuristic; only the coverage snapshot lets this combination gate (todo.md §J, §17.2).",
        verdict_effect: VerdictEffect::Gating,
    },
    // -- dead_code.rs (Deep Tier, `--features deep`) -----------------------
    RuleMetadata {
        id: "unused-pub-workspace",
        evidence_class: EvidenceClass::BoundedSemantic,
        preconditions: "Requires `--features deep` and `cargo judge dead-code` (Deep Tier; semantic reachability isn't available at the Fast Tier).",
        exclusions: "Every workspace crate is treated as workspace-internal; does not yet distinguish a real `unused-pub-workspace` finding from `unused-pub-api` on a published crate (semver-sensitive, info-only) via the crate's `publish` field.",
        allowed_wording: "State as 'no reference found in the loaded workspace' — never as 'unused' outright or as clearance for deletion; external ecosystem usage is not_inferable (todo.md §17.3, §17.4).",
        verdict_effect: VerdictEffect::Gating,
    },
    // -- dep_graph.rs -----------------------------------------------------
    RuleMetadata {
        id: "duplicate-crate-versions",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `cargo judge deps`).",
        exclusions: "Requires a resolved `Cargo.lock`; runs its own full `cargo_metadata` resolve (not `--no-deps`), separate from the workspace-only ingest used elsewhere.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    RuleMetadata {
        id: "msrv-drift",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `cargo judge deps`).",
        exclusions: "Requires a resolved `Cargo.lock`; runs its own full `cargo_metadata` resolve (not `--no-deps`), separate from the workspace-only ingest used elsewhere.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    RuleMetadata {
        id: "workspace-dep-drift",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `cargo judge deps`).",
        exclusions: "Requires a resolved `Cargo.lock`; runs its own full `cargo_metadata` resolve (not `--no-deps`), separate from the workspace-only ingest used elsewhere.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    // -- deps.rs ------------------------------------------------------------
    RuleMetadata {
        id: "misplaced-dependency-kind",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `cargo judge deps`).",
        exclusions: "Only two unambiguous cases are implemented: a `normal` dependency used exclusively from `Dev`-domain files, and a `build` dependency never referenced from `build.rs`. Directory-convention classification (`tests/`/`examples/`/`benches/`) is heuristic, not module-graph resolution — an unconventionally wired file can be misclassified. A dependency with more than one declared feature is excluded from the `Dev`-domain case, since a longer feature list is itself weak evidence of broader use than identifier scanning can see.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
    },
    RuleMetadata {
        id: "unused-dev-dependency",
        evidence_class: EvidenceClass::BoundedSemantic,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `cargo judge deps`).",
        exclusions: "No usage found in `Dev`-domain files (`tests/`, `examples/`, `benches/`) or `#[cfg(test)]` modules of the declaring package; doctests are not scanned.",
        allowed_wording: BOUNDED_SEMANTIC_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    RuleMetadata {
        id: "heavy-dependency",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `cargo judge deps`).",
        exclusions: "Transitive-count and used-item thresholds are first-cut, adjustable constants, not a calibrated cost model.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
    },
    RuleMetadata {
        id: "unused-feature-flag",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `cargo judge deps`).",
        exclusions: "Does not cover well-known 'bundle' features (e.g. tokio's 'full' feature) when the dependency itself is used — recognizing those needs a per-dependency feature vocabulary judge does not maintain. Only fires for a dependency with zero usage found anywhere in the examined view.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    RuleMetadata {
        id: "default-features-unused",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `cargo judge deps`).",
        exclusions: "Does not cover 'used, but only non-default features' — telling default from non-default usage apart needs per-dependency feature-to-symbol knowledge judge does not have. Only fires when the manifest text explicitly sets `default-features = true` and zero usage was found anywhere in the examined view.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    // -- duplication.rs -------------------------------------------------
    RuleMetadata {
        id: "duplicate-code",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`/`audit` in `Mild` mode by default, and `cargo judge dupes` for any `--mode`).",
        exclusions: "This entry reflects the default `Strict`/`Mild` classification. `Weak` mode normalizes literal values to placeholders; `Semantic` mode additionally normalizes local variable/parameter identifiers — both are overridden to `Heuristic` at the finding-creation site (see `crate::duplication::CloneMember::to_finding`), not `derived_fact`.",
        allowed_wording: "For `Strict`/`Mild` matches: state as an exact token-equality fact (todo.md §17.3). For `Weak`/`Semantic` matches: phrase as a possible/similar match, never an exact duplicate — those modes normalize literals and/or identifiers, so the underlying code is not byte-identical.",
        verdict_effect: VerdictEffect::Gating,
    },
    // -- git.rs -----------------------------------------------------------
    RuleMetadata {
        id: "hotspot",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier, needs git history; part of bare `cargo judge`/`audit`'s hotspot block and `cargo judge health`).",
        exclusions: "Ranked complexity × churn over the last `DEFAULT_WINDOW_DAYS` (365) days, capped to the top `HOTSPOT_LIMIT` (15) files — a genuinely risky file that doesn't make the cap is not surfaced. A file rewritten for legitimate reasons (e.g. a planned refactor) scores the same as unplanned churn.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
    },
    // -- ownership.rs -------------------------------------------------------
    RuleMetadata {
        id: "low-bus-factor",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier, needs git history; part of bare `cargo judge`, `audit`, and `cargo judge distribution`).",
        exclusions: "Only fires when the repository has at least 2 distinct authors active within the analysis window — with a single repo-wide author every file is bus-factor 1 by construction, so the metric would be categorically inapplicable, not merely statistically weak (see GitHub issue #2: 586 commits, 1 author, 333 findings).",
        allowed_wording: "State a concrete git activity date as the fact; keep any 'knowledge risk' reading separate and explicitly a heuristic interpretation. Per todo.md §17.4: never state 'the author is inactive/doesn't know the code' as a fact.",
        verdict_effect: VerdictEffect::AdvisoryOnly,
    },
    RuleMetadata {
        id: "ownership-fragmentation",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier, needs git history; part of bare `cargo judge`, `audit`, and `cargo judge distribution`).",
        exclusions: "Only counted at ≥4 blamed authors, a top-author share below 35%, and ≥50 blamed lines — files below any of those thresholds are skipped as inconclusive. Blame is not a knowledge measurement.",
        allowed_wording: "many small blame shares — diffuse responsibility is one possible reading, not a proven problem (see `crate::ownership::OWNERSHIP_FRAGMENTATION_NOTE`, which must accompany every finding of this rule).",
        verdict_effect: VerdictEffect::AdvisoryOnly,
    },
    // -- pattern.rs (advisory-only design-pattern recommendations; never a
    // Finding — see that module's doc comment) ----------------------------
    RuleMetadata {
        id: "stringly-error-boundary",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires `cargo judge patterns` (or `explain-pattern`/`fix-preview`); not part of bare `cargo judge`, `audit`, or any Finding-producing report — never wired into `evidence_class_for_rule`, the health score, or a baseline verdict.",
        exclusions: "Requires ≥2 `catch-all-error` findings in the same crate plus at least one crate-local typed error definition (independently sourced signals); a single symptom, or symptoms without a typed error already present, produce no candidate. The boundary can be a deliberate compatibility shim rather than a design gap.",
        allowed_wording: "Every claim must be phrased as an observation with checkable evidence locations, never an absolute claim (todo.md §16.7 'Sprachdisziplin'); never state this is 'the best' pattern or that the current structure is definitely wrong (todo.md §17.4). Always pair with a contraindication.",
        verdict_effect: VerdictEffect::AdvisoryOnly,
    },
    RuleMetadata {
        id: "primitive-domain-value",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires `cargo judge patterns` (or `explain-pattern`/`fix-preview`); not part of bare `cargo judge`, `audit`, or any Finding-producing report — never wired into `evidence_class_for_rule`, the health score, or a baseline verdict.",
        exclusions: "Fast-Tier-reachable narrowing of the full todo.md §16.3 rule: only the same (parameter name, type) pair across ≥2 `pub fn` signatures in the same crate, restricted to primitive numeric/`String`/`&str` types (`bool` excluded — see `boolean-state-cluster`), with at least one signature guarding the parameter. No cross-crate reasoning, no non-syntactic evidence. A shared name/type pair can have different meanings across functions despite matching structurally.",
        allowed_wording: "Every claim must be phrased as an observation with checkable evidence locations, never an absolute claim (todo.md §16.7 'Sprachdisziplin'); never state this is 'the best' pattern or that the current structure is definitely wrong (todo.md §17.4). Always pair with a contraindication.",
        verdict_effect: VerdictEffect::AdvisoryOnly,
    },
    RuleMetadata {
        id: "boolean-state-cluster",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires `cargo judge patterns` (or `explain-pattern`/`fix-preview`); not part of bare `cargo judge`, `audit`, or any Finding-producing report — never wired into `evidence_class_for_rule`, the health score, or a baseline verdict.",
        exclusions: "Fast-Tier-reachable narrowing of the full todo.md §16.3 rule, scoped to a single function rather than cross-call-site: needs ≥3 `bool` parameters plus a condition/`match` combining ≥2 of them within the same function body; does not aggregate evidence about how bool parameters are combined across call sites.",
        allowed_wording: "Every claim must be phrased as an observation with checkable evidence locations, never an absolute claim (todo.md §16.7 'Sprachdisziplin'); never state this is 'the best' pattern or that the current structure is definitely wrong (todo.md §17.4). Always pair with a contraindication.",
        verdict_effect: VerdictEffect::AdvisoryOnly,
    },
    // -- provenance.rs ------------------------------------------------------
    RuleMetadata {
        id: "provenance-churn",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires git history with commit trailers/metadata; subcommand-only via `cargo judge provenance` — not part of bare `cargo judge`.",
        exclusions: "Commit trailers/markers are optional, unverified, and trivially fakeable; size/timing/style heuristics are weaker still.",
        allowed_wording: "Must always be shown together with `crate::provenance::PROVENANCE_CAVEAT`: a distribution trend, not a judgment on any single commit or person; never used to evaluate individual people or commits (todo.md §17.4, §3.G G6).",
        verdict_effect: VerdictEffect::AdvisoryOnly,
    },
    RuleMetadata {
        id: "provenance-duplication-rate",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires git history with commit trailers/metadata; subcommand-only via `cargo judge provenance` — not part of bare `cargo judge`.",
        exclusions: "Commit trailers/markers are optional, unverified, and trivially fakeable; attribution is via blame, which is not a knowledge measurement.",
        allowed_wording: "Must always be shown together with `crate::provenance::PROVENANCE_CAVEAT`: a distribution trend, not a judgment on any single commit or person; never used to evaluate individual people or commits (todo.md §17.4, §3.G G6).",
        verdict_effect: VerdictEffect::AdvisoryOnly,
    },
    RuleMetadata {
        id: "provenance-suppression-debt",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires git history with commit trailers/metadata; subcommand-only via `cargo judge provenance` — not part of bare `cargo judge`.",
        exclusions: "Commit trailers/markers are optional, unverified, and trivially fakeable; attribution is via blame, which is not a knowledge measurement.",
        allowed_wording: "Must always be shown together with `crate::provenance::PROVENANCE_CAVEAT`: a distribution trend, not a judgment on any single commit or person; never used to evaluate individual people or commits (todo.md §17.4, §3.G G6).",
        verdict_effect: VerdictEffect::AdvisoryOnly,
    },
    // -- slop.rs (G1 error-masking, G2 stub/theater-code, G3 lexical) -------
    RuleMetadata {
        id: "swallowed-result",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Syntax-only: only `let _ = fallible();` and a bare `.ok();` statement are matched; other ways of discarding a `Result` are not.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    RuleMetadata {
        id: "empty-error-arm",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only an empty `Err(_)`/`Err(..)` match arm, or an `if let Err(_) = ... { }` with no `else`, is matched.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    RuleMetadata {
        id: "catch-all-error",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only `pub fn` boundaries whose error type is erased (`Box<dyn Error>` / `anyhow::Error`) are matched; internal (non-`pub`) error erasure is out of scope.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    RuleMetadata {
        id: "suppression-debt",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block). Reported as `Severity::Info` for the current state only — trend-against-baseline is handled by the existing baseline/delta system.",
        exclusions: "Counts `#[allow(...)]`/`#[expect(...)]` attribute occurrences; does not judge whether any individual suppression is justified.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    RuleMetadata {
        id: "merged-stub",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only bare `todo!()`/`unimplemented!()` outside a `#[cfg(feature = ...)]`-gated scope; feature-gated stubs are excluded by design.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    RuleMetadata {
        id: "empty-impl",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only a function/method/trait-default with a doc comment and a literally empty body is matched; an empty body without a doc comment is not flagged.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    RuleMetadata {
        id: "assertion-free-test",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only the literal `#[test]` attribute (without `#[should_panic]`) is matched, not third-party test-framework attributes (`#[tokio::test]`, `#[rstest]`, ...). Syntactically assertion-free does not mean the test is ineffective — macros, propagated return errors, and helper functions can still exercise behavior.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    RuleMetadata {
        id: "tautological-test",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only the literal `assert!(true)` / `assert_eq!(x, x)` shapes are matched.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    RuleMetadata {
        id: "ignored-test-accumulation",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block). Reported as `Severity::Info` for the current state only — trend-against-baseline is handled by the existing baseline/delta system.",
        exclusions: "Only the literal `#[ignore]`/`#[ignore = \"...\"]` attribute is matched, not third-party test-framework equivalents.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    RuleMetadata {
        id: "conversational-artifact",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only plain `//`/`/* */` comments are scanned (raw source-text scan in `crate::slop_text`, since `syn` discards non-doc comments entirely); `///`/`//!` doc comments are out of scope for this rule.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    RuleMetadata {
        id: "restating-comment",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only plain `//`/`/* */` comments are scanned (raw source-text scan in `crate::slop_text`); `///`/`//!` doc comments are out of scope for this rule (see `doc-restates-signature`).",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    RuleMetadata {
        id: "step-comment-inflation",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only plain `//`/`/* */` comments are scanned (raw source-text scan in `crate::slop_text`); requires a chain of three or more `// Step N:`-shaped comments.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    RuleMetadata {
        id: "generic-naming",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only an identifier that is exactly a fixed placeholder word (`data`, `temp`, `handler`, ...) is flagged; a poorly named identifier outside that list is not.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    RuleMetadata {
        id: "doc-restates-signature",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only a doc comment that is a pure signature echo is flagged; a doc comment that adds any information beyond the signature is not.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    // -- slop_structural.rs (G4, Fast Tier subset) ---------------------------
    RuleMetadata {
        id: "churn-hotspot",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier, needs git history; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "14-day window, first-cut commit-count threshold; a file rewritten for legitimate reasons (e.g. a planned refactor) scores the same as unplanned rework.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
    },
    RuleMetadata {
        id: "complexity-inflation",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Flags a long function with implausibly low branching; does not distinguish a genuinely simple long function (e.g. a large match/data table) from a padded one.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
    },
    RuleMetadata {
        id: "legacy-freeze",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier, needs git history; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "12-month window; a file that is stable because it is finished looks identical to one that is stale/abandoned.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
    },
    RuleMetadata {
        id: "abstraction-inflation",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Covers three sub-patterns (single-impl trait, delegating wrapper, builder for a small struct) via `evidence.kind`; a deliberate abstraction seam kept for testability/future extension looks structurally identical to an unnecessary one.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
    },
    // -- slop_structural_deep.rs (G4 remainder, Deep Tier, `--features deep`)
    RuleMetadata {
        id: "duplicative-reinvention",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires `--features deep` and `cargo judge dead-code` (Deep Tier; needs `find_all_refs` cross-file reference data). Reported as `Severity::Info` for the current state only — trend-against-baseline is handled by the existing baseline/delta system.",
        exclusions: "Test/bench-attributed functions and methods inside `impl TraitName for SomeType` blocks are excluded from the candidate set entirely, not down-weighted — trait-impl methods are routinely invoked through operator/macro sugar `find_all_refs` can't see (e.g. `Display::fmt`, `Iterator::next`, `Drop::drop`), so they would otherwise look structurally unwired even when used everywhere.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
    },
    RuleMetadata {
        id: "connectivity-drop",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires `--features deep` and `cargo judge dead-code` (Deep Tier; needs `find_all_refs` cross-file reference data). Reported as `Severity::Info` for the current state only — trend-against-baseline is handled by the existing baseline/delta system.",
        exclusions: "Test/bench-attributed functions and methods inside `impl TraitName for SomeType` blocks are excluded from the candidate set entirely, not down-weighted — trait-impl methods are routinely invoked through operator/macro sugar `find_all_refs` can't see (e.g. `Display::fmt`, `Iterator::next`, `Drop::drop`), so they would otherwise look structurally unwired even when used everywhere.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
    },
    // -- slopsquat.rs (G5) ----------------------------------------------------
    RuleMetadata {
        id: "name-collision-risk",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier, fully local/offline; part of bare `cargo judge`, `audit`, and `cargo judge deps`).",
        exclusions: "Levenshtein-distance match against a manually curated, potentially stale static list of well-known crates (`data/popular_crates.txt`); neither exhaustive nor auto-updated.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
    },
    RuleMetadata {
        id: "phantom-crate",
        evidence_class: EvidenceClass::ExternalMeasurement,
        preconditions: "Requires `cargo judge deps --check-crates-io` (opt-in network access to the crates.io sparse index).",
        exclusions: "A snapshot at lookup time — a crate published moments after the check ran is indistinguishable from one that never existed.",
        allowed_wording: EXTERNAL_MEASUREMENT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    RuleMetadata {
        id: "phantom-version",
        evidence_class: EvidenceClass::ExternalMeasurement,
        preconditions: "Requires `cargo judge deps --check-crates-io` (opt-in network access to the crates.io sparse index).",
        exclusions: "A snapshot at lookup time — a matching version published or un-yanked moments after the check ran is indistinguishable from one that never existed.",
        allowed_wording: EXTERNAL_MEASUREMENT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
    RuleMetadata {
        id: "fresh-low-reputation-dep",
        evidence_class: EvidenceClass::ExternalMeasurement,
        preconditions: "Requires `cargo judge deps --check-crates-io` (opt-in network access to the crates.io REST API).",
        exclusions: "Download counts and repository-link presence are the crates.io REST API's own signals, not something judge independently verifies; a snapshot at lookup time.",
        allowed_wording: EXTERNAL_MEASUREMENT_WORDING,
        verdict_effect: VerdictEffect::Gating,
    },
];

/// Looks up one rule's fixed documentation by id. `None` for an id not in
/// [`RULE_REGISTRY`] — the CLI turns that into a usage error, not a panic.
pub fn lookup(rule_id: &str) -> Option<&'static RuleMetadata> {
    RULE_REGISTRY.iter().find(|entry| entry.id == rule_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every registry entry's `verdict_effect` must agree with
    /// `evidence_class.is_gating()` — the single place this policy actually
    /// lives (see [`EvidenceClass::is_gating`]). Prevents the two fields from
    /// drifting apart as rules are added or reclassified.
    #[test]
    fn verdict_effect_matches_evidence_class_is_gating_for_every_entry() {
        for entry in RULE_REGISTRY {
            let expected = if entry.evidence_class.is_gating() {
                VerdictEffect::Gating
            } else {
                VerdictEffect::AdvisoryOnly
            };
            assert_eq!(
                entry.verdict_effect, expected,
                "rule `{}`: verdict_effect does not match evidence_class.is_gating()",
                entry.id
            );
        }
    }

    /// Every rule id constant defined outside the Deep Tier (`--features
    /// deep`) has a registry entry — the completeness guarantee from todo.md
    /// §17.5. Constants are imported explicitly, one per rule, so a new rule
    /// id added anywhere in the crate without a matching registry entry fails
    /// this test instead of silently falling through `lookup`.
    #[test]
    fn every_fast_tier_rule_id_has_a_registry_entry() {
        let ids: &[&str] = &[
            crate::boundaries::BOUNDARY_VIOLATION_RULE,
            crate::boundaries::DEPENDENCY_CYCLE_RULE,
            crate::coverage::UNTESTED_HOTSPOT_RULE,
            crate::dep_graph::DUPLICATE_CRATE_VERSIONS_RULE,
            crate::dep_graph::MSRV_DRIFT_RULE,
            crate::dep_graph::WORKSPACE_DEP_DRIFT_RULE,
            crate::deps::MISPLACED_DEPENDENCY_KIND_RULE,
            crate::deps::UNUSED_DEV_DEPENDENCY_RULE,
            crate::deps::HEAVY_DEPENDENCY_RULE,
            crate::deps::UNUSED_FEATURE_FLAG_RULE,
            crate::deps::DEFAULT_FEATURES_UNUSED_RULE,
            crate::duplication::DUPLICATE_RULE,
            crate::git::HOTSPOT_RULE,
            crate::ownership::LOW_BUS_FACTOR_RULE,
            crate::ownership::OWNERSHIP_FRAGMENTATION_RULE,
            crate::pattern::STRINGLY_ERROR_BOUNDARY_RULE,
            crate::pattern::PRIMITIVE_DOMAIN_VALUE_RULE,
            crate::pattern::BOOLEAN_STATE_CLUSTER_RULE,
            crate::provenance::PROVENANCE_CHURN_RULE,
            crate::provenance::PROVENANCE_DUPLICATION_RATE_RULE,
            crate::provenance::PROVENANCE_SUPPRESSION_DEBT_RULE,
            crate::slop::SWALLOWED_RESULT_RULE,
            crate::slop::EMPTY_ERROR_ARM_RULE,
            crate::slop::CATCH_ALL_ERROR_RULE,
            crate::slop::SUPPRESSION_DEBT_RULE,
            crate::slop::MERGED_STUB_RULE,
            crate::slop::EMPTY_IMPL_RULE,
            crate::slop::ASSERTION_FREE_TEST_RULE,
            crate::slop::TAUTOLOGICAL_TEST_RULE,
            crate::slop::IGNORED_TEST_ACCUMULATION_RULE,
            crate::slop::CONVERSATIONAL_ARTIFACT_RULE,
            crate::slop::RESTATING_COMMENT_RULE,
            crate::slop::STEP_COMMENT_INFLATION_RULE,
            crate::slop::GENERIC_NAMING_RULE,
            crate::slop::DOC_RESTATES_SIGNATURE_RULE,
            crate::slop_structural::CHURN_HOTSPOT_RULE,
            crate::slop_structural::COMPLEXITY_INFLATION_RULE,
            crate::slop_structural::LEGACY_FREEZE_RULE,
            crate::slop_structural::ABSTRACTION_INFLATION_RULE,
            crate::slopsquat::NAME_COLLISION_RISK_RULE,
            crate::slopsquat::PHANTOM_CRATE_RULE,
            crate::slopsquat::PHANTOM_VERSION_RULE,
            crate::slopsquat::FRESH_LOW_REPUTATION_DEP_RULE,
        ];
        for id in ids {
            assert!(
                lookup(id).is_some(),
                "rule id `{id}` has no RULE_REGISTRY entry"
            );
        }
    }

    /// Same completeness guarantee for the three rule ids only defined when
    /// the crate is built with `--features deep` (`dead_code`,
    /// `slop_structural_deep`) — kept in a separate, `cfg`-gated test since
    /// those constants don't exist in a Fast-Tier-only build.
    #[cfg(feature = "deep")]
    #[test]
    fn every_deep_tier_rule_id_has_a_registry_entry() {
        let ids: &[&str] = &[
            crate::dead_code::UNUSED_PUB_WORKSPACE_RULE,
            crate::slop_structural_deep::DUPLICATIVE_REINVENTION_RULE,
            crate::slop_structural_deep::CONNECTIVITY_DROP_RULE,
        ];
        for id in ids {
            assert!(
                lookup(id).is_some(),
                "rule id `{id}` has no RULE_REGISTRY entry"
            );
        }
    }

    /// (a) A known rule id resolves, with the evidence class matching the
    /// authoritative mapping in [`crate::finding::evidence_class_for_rule`]
    /// (for rules that mapping actually classifies — `duplicate-code`'s
    /// default classification and the three `pattern` rules deliberately
    /// diverge, see their entries' `exclusions`/module docs).
    #[test]
    fn known_rule_id_resolves_with_expected_fields() {
        let entry = lookup(crate::slop::CATCH_ALL_ERROR_RULE).expect("catch-all-error entry");
        assert_eq!(entry.id, "catch-all-error");
        assert_eq!(entry.evidence_class, EvidenceClass::DerivedFact);
        assert_eq!(entry.verdict_effect, VerdictEffect::Gating);
        assert!(!entry.preconditions.is_empty());
        assert!(!entry.exclusions.is_empty());
        assert!(!entry.allowed_wording.is_empty());
    }

    /// (b) An unknown rule id resolves to `None` — the CLI turns this into
    /// exit code 2, never a panic or a silent empty result.
    #[test]
    fn unknown_rule_id_does_not_resolve() {
        assert!(lookup("not-a-real-rule").is_none());
    }
}
