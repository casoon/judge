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
    /// A minimal, self-contained illustration of what triggers this rule,
    /// for an audience outside judge itself (e.g. a project landing page) —
    /// deliberately separate from `allowed_wording`, which constrains a
    /// finding's own printed text, not marketing/documentation copy. `None`
    /// where no curated example exists yet; not every rule has one.
    pub example: Option<RuleExample>,
}

/// One rule's curated example: minimal source plus a plain-language reason
/// it matters. `before` is meant to be kept identical to (or copied by) a
/// canonical positive test for the same rule — see each usage site below —
/// so an example can never silently drift from what the rule actually
/// flags: if the detector's behavior changes enough to stop matching, that
/// shared test fails.
#[derive(Debug, Clone, Copy)]
pub struct RuleExample {
    pub before: &'static str,
    pub why_it_matters: &'static str,
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
    // -- api_surface.rs ---------------------------------------------------
    RuleMetadata {
        id: "undocumented-public-item",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; `cargo judge api-surface`, subcommand-only).",
        exclusions: "Checks only whether the item itself is written `pub`, not the full visibility chain up through enclosing modules — a `pub fn` inside a private `mod` is not actually reachable from outside the crate but is still checked (see `crate::api_surface` module docs). Scoped to free `fn`/`struct`/`enum`/`trait`/`const`/`static`/`type` at module level plus inherent-impl methods; methods inside `impl Trait for Type` are exempt (typically inherit the trait's own documentation), as are `#[test]`-attributed functions and anything gated by `#[cfg(test)]`.",
        allowed_wording: "State only that no doc comment was found on this `pub` item — never that its documentation is 'bad' or 'incomplete' (todo.md §17.4).",
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "semver-hazard",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; `cargo judge api-surface`, subcommand-only).",
        exclusions: "Covers two of the three todo.md §I sub-cases via `evidence.kind`: a `pub enum` with at least two variants and no `#[non_exhaustive]` attribute (`missing_non_exhaustive_enum`; a single-variant enum is exempt), and a `pub struct` with at least one `pub` field and no `#[non_exhaustive]` attribute (`missing_non_exhaustive_struct_fields`; a unit struct or one with only private fields is exempt). The third sub-case — a dependency's type leaking through a public signature — needs type resolution across crate boundaries the Fast Tier doesn't have and is not implemented. Same `#[cfg(test)]`/generated-code exemptions as `undocumented-public-item`.",
        allowed_wording: "State only the exact syntax fact (attribute absence plus variant/field count) — never that the type is 'badly designed'; adding a variant/field is a known Rust API-evolvability fact, not this crate's opinion (todo.md §17.4).",
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    // -- boundaries.rs --------------------------------------------------
    RuleMetadata {
        id: "crate-boundary-violation",
        evidence_class: EvidenceClass::BoundedSemantic,
        preconditions: "Requires a `judge.toml` with `[[boundary]]`/`[layers]` config; opt-in — `cargo judge boundaries` (and the boundaries block of bare `cargo judge`/`audit`) does nothing without it.",
        exclusions: "Scoped to crate-level dependency edges only, fully knowable from `cargo_metadata` without a build; module-level boundaries need semantic module resolution the Fast Tier doesn't have yet.",
        allowed_wording: BOUNDED_SEMANTIC_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "dependency-cycle",
        evidence_class: EvidenceClass::BoundedSemantic,
        preconditions: "Requires a `judge.toml` with `[[boundary]]`/`[layers]` config; opt-in — `cargo judge boundaries` (and the boundaries block of bare `cargo judge`/`audit`) does nothing without it.",
        exclusions: "Scoped to crate-level dependency edges only, fully knowable from `cargo_metadata` without a build; module-level cycles need semantic module resolution the Fast Tier doesn't have yet.",
        allowed_wording: BOUNDED_SEMANTIC_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "feature-graph-cycle",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`/`audit`) — deliberately not gated behind `judge.toml` the way `dependency-cycle` is: a `[features]` table is either cyclic or it isn't, needing no project-intent config to interpret (see `crate::boundaries` module docs 'feature-graph-cycle').",
        exclusions: "Reuses `dependency-cycle`'s own cycle-finding algorithm over a different graph: nodes are one crate's own declared feature names, edges are implication-list entries that exactly match another feature of the same package. A `dep:foo`/`pkg/feat`/`pkg?/feat` entry (a dependency activation, not a sibling feature) is excluded. Cargo tolerates a cyclic feature graph at resolution time — this is a structural-hygiene signal, not a claim the build is broken.",
        allowed_wording: "State only that this cyclic chain of feature implications exists — never that the crate 'fails to build' or that the cycle is 'a bug' (todo.md §17.4).",
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "change-coupling-signal",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires a `judge.toml` with `[layers]` configured (a non-empty `assign` table) — with no layer config, this performs no analysis at all rather than guessing which crates 'should' be independent (todo.md §17 'Kein Raten von Projektabsicht'). Part of the same `judge.toml`-gated block as `dependency-cycle`/`crate-boundary-violation` in bare `cargo judge`/`audit`.",
        exclusions: "Co-change is counted per commit at crate granularity (a crate is 'touched' if any of its files appear in the commit), not per file pair. `MIN_CO_CHANGE_SAMPLE` (5) and `CHANGE_COUPLING_RATIO_THRESHOLD` (0.6) are first-cut, adjustable constants, not calibrated against a corpus of known-coupled vs. known-independent crate pairs. A large repo-wide commit (a rename, a formatting pass) can make unrelated crates look coupled for one window.",
        allowed_wording: "State only the co-change count and ratio for this crate pair within the examined git window — never that the crates 'are coupled' or 'violate the architecture' as settled fact (todo.md §17.4).",
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    RuleMetadata {
        id: "module-boundary-violation",
        evidence_class: EvidenceClass::BoundedSemantic,
        preconditions: "Requires a `judge.toml` with `[[module_boundary]]` config; opt-in — `cargo judge boundaries` (and the boundaries block of bare `cargo judge`/`audit`) does nothing without it.",
        exclusions: "Module path resolution is a directory-convention heuristic, not `mod`-graph resolution — a file wired into the build unconventionally (e.g. a `#[path = \"...\"]` attribute) is missed (see `crate::boundaries` module docs 'Module-level boundaries'). Only `direct` reach is supported — `transitive` would need a real module call graph, which the Fast Tier doesn't have; requesting it is a config error, not a silent downgrade. Only `forbidden` is supported, not `required` (crate-level boundaries' other half).",
        allowed_wording: BOUNDED_SEMANTIC_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    // -- api_surface_deep.rs (Deep Tier, `--features deep`) ---------------
    RuleMetadata {
        id: "internal-leak",
        evidence_class: EvidenceClass::BoundedSemantic,
        preconditions: "Requires `--features deep` and `cargo judge api-surface` (same subcommand as `semver-hazard`'s `leaked_dependency_type` sub-case, which this rule reuses the type resolution of), plus a `judge.toml` with a non-empty `internal_crates` list (see `crate::boundaries::BoundaryConfig::internal_crates`). With `internal_crates` empty or absent (the default), this rule performs no analysis at all and emits zero findings — that must never be read as 'no internal leaks found', only that none were checked for (todo.md §17 'Kein Raten von Projektabsicht': an architecture rule needs explicit config, not a guess).",
        exclusions: "Same resolution and the same documented boundary as `semver-hazard`'s `leaked_dependency_type` sub-case (see `crate::api_surface_deep` module docs 'Ehrliche Grenze'): only direct parameter/return types plus one level of generic unwrapping through a `std`/`core`/`alloc` container are checked; a `dyn Trait` receiver, raw pointer, function pointer, tuple, or slice/array element type is not unwrapped.",
        allowed_wording: "State only that this pub item's signature resolves to a type defined in `<crate>`, which is configured as internal — never that crossing this boundary is 'unintentional' or that the crate's public API is 'broken' (todo.md §17.4); judge does not know whether crossing the boundary was deliberate.",
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "module-boundary-violation-deep",
        evidence_class: EvidenceClass::BoundedSemantic,
        preconditions: "Requires `--features deep` and a `judge.toml` with `[[module_boundary]]` config; runs alongside (not instead of) the Fast-Tier `module-boundary-violation` check in `cargo judge boundaries` — see `crate::boundaries_deep` module docs.",
        exclusions: "Real Deep-Tier symbol reference resolution replaces the Fast Tier's `syn`-based text scan for the *reference edge* itself (catching a re-export or aliased `use` the text scan misses), but the `from`/`forbidden` module-path *scoping* is still the same directory-convention heuristic as the Fast-Tier rule. Only free functions, inherent/trait-impl methods, and trait default methods are checked as the referenced item — unlike the Fast-Tier text scan, which is item-kind-agnostic, this Deep-Tier pass does not yet cover structs/enums/traits/consts/statics. `Reach::Transitive` is not supported here either, same restriction as the Fast Tier.",
        allowed_wording: BOUNDED_SEMANTIC_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "re-export-chain",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires `--features deep` and `cargo judge api-surface` (same subcommand as `semver-hazard`/`internal-leak`); always evaluated when the Deep Tier is available, no `judge.toml` config needed.",
        exclusions: "Only a plain, non-glob, non-braced `pub use path::Item;` (optionally renamed) at a file's own module-root level is considered a candidate or an intermediate hop — a `pub use` nested inside an inline `mod { .. }` block in the same file, a glob (`pub use foo::*;`), or a braced group (`pub use foo::{A, B};`) is invisible to this scan (see `crate::api_surface_deep` module docs). A hop count capped at 5 (`RE_EXPORT_CHAIN_MAX_HOPS`) is reported as `evidence.capped: true` rather than an exact count — chosen to bound the walk against a `pub use` cycle, not derived from a study of real-world chain depths. A single direct re-export (hop count 1) is deliberately never flagged — only 2 or more hops are, since curated top-level re-exports, prelude modules, and workspace umbrella crates routinely add exactly one hop and are not themselves a sign of obscured ownership.",
        allowed_wording: "State only that this item's public path resolves through `<hop_count>` `pub use` hops before reaching its defining module `<defining_path>` — when `evidence.capped` is true, phrase `<hop_count>` as 'at least 5', not an exact count; never phrase a chain's existence as 'bad practice' or as 'hiding implementation details' (todo.md §17.4) — re-export facades are a common, legitimate pattern judge cannot tell apart from an unintentional one.",
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    // -- coverage.rs ------------------------------------------------------
    RuleMetadata {
        id: "untested-hotspot",
        evidence_class: EvidenceClass::ExternalMeasurement,
        preconditions: "Requires `cargo judge coverage --lcov <path>` — an externally generated `cargo-llvm-cov` LCOV report; judge never measures coverage itself, only imports an already-generated snapshot.",
        exclusions: "Complexity and churn inputs are `derived_fact`/`heuristic` in isolation, but the imported coverage snapshot is the rarest, least locally-verifiable ingredient, so it sets the class for the combination.",
        allowed_wording: "State as the result of the imported coverage/complexity/churn snapshot — never a timeless truth. Complexity/churn inputs alone would only be heuristic; only the coverage snapshot lets this combination gate (todo.md §J, §17.2).",
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    // -- dead_code.rs (Deep Tier, `--features deep`) -----------------------
    RuleMetadata {
        id: "unused-pub-workspace",
        evidence_class: EvidenceClass::BoundedSemantic,
        preconditions: "Requires `--features deep` and `cargo judge dead-code` (Deep Tier; semantic reachability isn't available at the Fast Tier).",
        exclusions: "Every workspace crate is treated as workspace-internal; a crate whose resolved `publish` field allows publishing gets `unused-pub-api` instead of this rule for the same underlying condition (see `crate::dead_code::publishable_crates`).",
        allowed_wording: "State as 'no reference found in the loaded workspace' — never as 'unused' outright or as clearance for deletion; external ecosystem usage is not_inferable (todo.md §17.3, §17.4).",
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "unused-pub-api",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires `--features deep` and `cargo judge dead-code` (Deep Tier; semantic reachability isn't available at the Fast Tier). Only emitted for items belonging to a crate whose resolved `publish` field allows publishing (`None`, or `Some` of a non-empty registry list — only `Some(vec![])`, i.e. `publish = false`, is excluded).",
        exclusions: "Same reachability query and same 'every workspace crate is workspace-internal' scope as `unused-pub-workspace`; a published crate's whole purpose is exposing API to consumers outside the loaded workspace, so 'zero internal reference' is the expected normal state for most of a healthy library's public surface, not a defect signal — that is why this is `Heuristic`/advisory rather than `unused-pub-workspace`'s `BoundedSemantic`/gating.",
        allowed_wording: "State as 'no reference found within the examined workspace; this crate is published, so external ecosystem usage is not inferable and expected' — never as 'unused' or as clearance for deletion (todo.md §17.3, §17.4).",
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    RuleMetadata {
        id: "dead-enum-variant",
        evidence_class: EvidenceClass::BoundedSemantic,
        preconditions: "Requires `--features deep` and `cargo judge dead-code` (Deep Tier; semantic reachability isn't available at the Fast Tier).",
        exclusions: "Every workspace crate is treated as workspace-internal, same simplification as `unused-pub-workspace`. Only a `pub` enum's variants are checked. Construction-vs-pattern classification is a `syn` re-parse of each file `crate::deep::referencing_files` reports as referencing the variant, looking for `Expr::Path`/`Expr::Call`/`Expr::Struct` occurrences of the variant's trailing path segment; `syn` parses a macro invocation's body as an opaque token stream, so a variant constructed only inside a macro call (e.g. `some_macro!(MyEnum::Variant)`) is invisible to this scan and can be misreported as having no construction site.",
        allowed_wording: "State as 'no construction site found in the examined workspace view' — never 'never constructed' or 'dead' outright (todo.md §17.3, §17.4).",
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "test-only-pub",
        evidence_class: EvidenceClass::BoundedSemantic,
        preconditions: "Requires `--features deep` and `cargo judge dead-code` (Deep Tier; semantic reachability isn't available at the Fast Tier).",
        exclusions: "Every workspace crate is treated as workspace-internal, same simplification as `unused-pub-workspace`; does not narrow by a crate's `publish` field the way `unused-pub-api` does. Runs the entry-point reachability query twice per checked item (once production-only, once counting tests) — real, accepted extra Deep Tier query volume.",
        allowed_wording: "State as 'reachable only through #[cfg(test)]/test-target code in the examined workspace view' — never a prescriptive claim like 'should be pub(crate)' (todo.md §17.3, §17.4).",
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    // -- dep_graph.rs -----------------------------------------------------
    RuleMetadata {
        id: "duplicate-crate-versions",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `cargo judge deps`).",
        exclusions: "Requires a resolved `Cargo.lock`; runs its own full `cargo_metadata` resolve (not `--no-deps`), separate from the workspace-only ingest used elsewhere.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "msrv-drift",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `cargo judge deps`).",
        exclusions: "Requires a resolved `Cargo.lock`; runs its own full `cargo_metadata` resolve (not `--no-deps`), separate from the workspace-only ingest used elsewhere.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "workspace-dep-drift",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `cargo judge deps`).",
        exclusions: "Requires a resolved `Cargo.lock`; runs its own full `cargo_metadata` resolve (not `--no-deps`), separate from the workspace-only ingest used elsewhere.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    // -- deps.rs ------------------------------------------------------------
    RuleMetadata {
        id: "misplaced-dependency-kind",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `cargo judge deps`).",
        exclusions: "Only two unambiguous cases are implemented: a `normal` dependency used exclusively from `Dev`-domain files, and a `build` dependency never referenced from `build.rs`. Directory-convention classification (`tests/`/`examples/`/`benches/`) is heuristic, not module-graph resolution — an unconventionally wired file can be misclassified. A dependency with more than one declared feature is excluded from the `Dev`-domain case, since a longer feature list is itself weak evidence of broader use than identifier scanning can see.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    RuleMetadata {
        id: "unused-dev-dependency",
        evidence_class: EvidenceClass::BoundedSemantic,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `cargo judge deps`).",
        exclusions: "No usage found in `Dev`-domain files (`tests/`, `examples/`, `benches/`) or `#[cfg(test)]` modules of the declaring package; doctests are not scanned.",
        allowed_wording: BOUNDED_SEMANTIC_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "heavy-dependency",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `cargo judge deps`).",
        exclusions: "Transitive-count and used-item thresholds are first-cut, adjustable constants, not a calibrated cost model.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    RuleMetadata {
        id: "unused-feature-flag",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `cargo judge deps`).",
        exclusions: "Does not cover well-known 'bundle' features (e.g. tokio's 'full' feature) when the dependency itself is used — recognizing those needs a per-dependency feature vocabulary judge does not maintain. Only fires for a dependency with zero usage found anywhere in the examined view.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "default-features-unused",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `cargo judge deps`).",
        exclusions: "Does not cover 'used, but only non-default features' — telling default from non-default usage apart needs per-dependency feature-to-symbol knowledge judge does not have. Only fires when the manifest text explicitly sets `default-features = true` and zero usage was found anywhere in the examined view.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "unused-feature",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `cargo judge deps`).",
        exclusions: "About a crate's own declared `[features]` table, not a dependency's features (see `unused-feature-flag`, the opposite direction). Never fires for `default`, or for a feature whose own value list is non-empty (an umbrella/bundle feature enabling other features/deps — a real effect even with no direct `cfg` reference). The same-crate reference check is a plain substring scan for `feature = \"x\"`/`feature=\"x\"` across the crate's own authored source, not a `syn`/token-tree parse of the `cfg` predicate — unusual whitespace around the `=` would be missed.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "unused-dependency",
        evidence_class: EvidenceClass::BoundedSemantic,
        preconditions: "Opt-in only: `cargo judge deps --check-rustc-lints` — runs a full `cargo check --workspace --all-targets` with rustc's stable `unused_crate_dependencies` lint enabled; never part of bare `cargo judge`, `audit`, or `cargo judge deps` without the flag (a full compile is a different order of cost than this module's other, instant syntactic passes).",
        exclusions: "Restricted to `normal` dependencies (`dev`/`build` are out of scope; `dev-dependencies` has its own `unused-dev-dependency` detector). Only fires when rustc's lint reports the dependency unused in every target compiled for the package — a dependency used by only one target (e.g. only from a `[[test]]`) is a known, documented multi-target false positive of the raw lint and is deliberately not flagged (see `crate::deps` module docs). A workspace that does not currently compile produces a report error from this detector, never a finding.",
        allowed_wording: BOUNDED_SEMANTIC_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "dep-without-repo",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `cargo judge deps`). Reads a dependency's own manifest via the same full, non `--no-deps` `cargo_metadata` resolve as `heavy-dependency`, since the primary `--no-deps` ingest cannot see a dependency's own manifest fields.",
        exclusions: "Fires when the dependency's own `repository` field is absent or blank. A missing field is not itself a defect — private/internal crates legitimately omit it, and the finding never claims otherwise (`Severity::Info`).",
        allowed_wording: "State only that no `repository` field was found in the dependency's own manifest — never that the dependency is 'untrustworthy' or 'suspicious' (that framing belongs to the separate `fresh-low-reputation-dep`/`phantom-crate` rules).",
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    // -- duplication.rs -------------------------------------------------
    RuleMetadata {
        id: "duplicate-code",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`/`audit` in `Mild` mode by default, and `cargo judge dupes` for any `--mode`).",
        exclusions: "This entry reflects the default `Strict`/`Mild` classification. `Weak` mode normalizes literal values to placeholders; `Semantic` mode additionally normalizes local variable/parameter identifiers — both are overridden to `Heuristic` at the finding-creation site (see `crate::duplication::CloneMember::to_finding`), not `derived_fact`.",
        allowed_wording: "For `Strict`/`Mild` matches: state as an exact token-equality fact (todo.md §17.3). For `Weak`/`Semantic` matches: phrase as a possible/similar match, never an exact duplicate — those modes normalize literals and/or identifiers, so the underlying code is not byte-identical.",
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    // -- git.rs -----------------------------------------------------------
    RuleMetadata {
        id: "hotspot",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier, needs git history; part of bare `cargo judge`/`audit`'s hotspot block and `cargo judge health`).",
        exclusions: "Ranked complexity × recency-weighted churn (exponential decay, `RECENCY_HALF_LIFE_DAYS` half-life) over the last `DEFAULT_WINDOW_DAYS` (365) days, capped to the top `HOTSPOT_LIMIT` (15) files — a genuinely risky file that doesn't make the cap is not surfaced. A file rewritten for legitimate reasons (e.g. a planned refactor) scores the same as unplanned churn.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    RuleMetadata {
        id: "size-distribution",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier, no git history needed — pure per-file LOC plus per-crate aggregation over the loaded workspace; part of bare `cargo judge` and `audit`).",
        exclusions: "First-cut, adjustable Gini threshold (`SIZE_DISTRIBUTION_GINI_THRESHOLD`, 0.6, mirrors `crate::duplication::DEFAULT_MIN_TOKENS`'s style); only fires when a file's LOC is in its crate's top decile *and* the crate's own file-size Gini coefficient exceeds the threshold — a large, concentrated file (e.g. a CLI dispatch table or an enum-heavy config module) is routinely legitimate, not a defect. A crate with only one authored file always has Gini `0.0` by construction and never fires.",
        allowed_wording: "State only the file's LOC, the crate's file count, and the crate's Gini coefficient against the threshold — never that the file 'is too big' or 'needs refactoring' (todo.md §17.4).",
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    // -- module_graph.rs ------------------------------------------------
    RuleMetadata {
        id: "unlinked-file",
        evidence_class: EvidenceClass::BoundedSemantic,
        preconditions: "Always evaluated (Fast Tier; `cargo judge module-graph`, subcommand-only).",
        exclusions: "Resolves `mod` declarations (including `#[path = \"...\"]`) from every recognized Cargo target root (`lib`, `bin`, `test`, `example`, `bench`, `build.rs`); a file spliced in only via `include!(...)` has no `mod` declaration and is invisible to this scan, so it is misreported as unlinked (see module docs 'Known blind spot: include!'). Generated files are excluded by default (see `crate::ingest::SourceKind`).",
        allowed_wording: BOUNDED_SEMANTIC_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "orphan-module",
        evidence_class: EvidenceClass::BoundedSemantic,
        preconditions: "Always evaluated (Fast Tier; `cargo judge module-graph`, subcommand-only).",
        exclusions: "Only resolves `crate::`/`super::`/`<crate-name>::`-qualified references, plus the narrow same-file `mod foo; use foo::...;` bare-reference exception (see module docs); any other bare/self-relative reference is not resolved, so a module referenced only that way can be misreported as orphaned. Modules containing a recognized entry point (`fn main`, a `#[test]`-like function) are exempt. Scoped to file-backed (`mod foo;`) module nodes; inline `mod foo { .. }` blocks have no file of their own and are not checked.",
        allowed_wording: BOUNDED_SEMANTIC_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    // -- ownership.rs -------------------------------------------------------
    RuleMetadata {
        id: "low-bus-factor",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier, needs git history; part of bare `cargo judge`, `audit`, and `cargo judge distribution`).",
        exclusions: "Only fires when the repository has at least 2 distinct authors active within the analysis window — with a single repo-wide author every file is bus-factor 1 by construction, so the metric would be categorically inapplicable, not merely statistically weak (see GitHub issue #2: 586 commits, 1 author, 333 findings).",
        allowed_wording: "State a concrete git activity date as the fact; keep any 'knowledge risk' reading separate and explicitly a heuristic interpretation. Per todo.md §17.4: never state 'the author is inactive/doesn't know the code' as a fact.",
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    RuleMetadata {
        id: "ownership-fragmentation",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier, needs git history; part of bare `cargo judge`, `audit`, and `cargo judge distribution`).",
        exclusions: "Only counted at ≥4 blamed authors, a top-author share below 35%, and ≥50 blamed lines — files below any of those thresholds are skipped as inconclusive. Blame is not a knowledge measurement.",
        allowed_wording: "many small blame shares — diffuse responsibility is one possible reading, not a proven problem (see `crate::ownership::OWNERSHIP_FRAGMENTATION_NOTE`, which must accompany every finding of this rule).",
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
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
        example: None,
    },
    RuleMetadata {
        id: "primitive-domain-value",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires `cargo judge patterns` (or `explain-pattern`/`fix-preview`); not part of bare `cargo judge`, `audit`, or any Finding-producing report — never wired into `evidence_class_for_rule`, the health score, or a baseline verdict.",
        exclusions: "Fast-Tier-reachable narrowing of the full todo.md §16.3 rule: only the same (parameter name, type) pair across ≥2 `pub fn` signatures in the same crate, restricted to primitive numeric/`String`/`&str` types (`bool` excluded — see `boolean-state-cluster`), with at least one signature guarding the parameter. No cross-crate reasoning, no non-syntactic evidence. A shared name/type pair can have different meanings across functions despite matching structurally.",
        allowed_wording: "Every claim must be phrased as an observation with checkable evidence locations, never an absolute claim (todo.md §16.7 'Sprachdisziplin'); never state this is 'the best' pattern or that the current structure is definitely wrong (todo.md §17.4). Always pair with a contraindication.",
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    RuleMetadata {
        id: "boolean-state-cluster",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires `cargo judge patterns` (or `explain-pattern`/`fix-preview`); not part of bare `cargo judge`, `audit`, or any Finding-producing report — never wired into `evidence_class_for_rule`, the health score, or a baseline verdict.",
        exclusions: "Fast-Tier-reachable narrowing of the full todo.md §16.3 rule, scoped to a single function rather than cross-call-site: needs ≥3 `bool` parameters plus a condition/`match` combining ≥2 of them within the same function body; does not aggregate evidence about how bool parameters are combined across call sites.",
        allowed_wording: "Every claim must be phrased as an observation with checkable evidence locations, never an absolute claim (todo.md §16.7 'Sprachdisziplin'); never state this is 'the best' pattern or that the current structure is definitely wrong (todo.md §17.4). Always pair with a contraindication.",
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    RuleMetadata {
        id: "public-invariant-bypass",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires `cargo judge patterns` (or `explain-pattern`/`fix-preview`); not part of bare `cargo judge`, `audit`, or any Finding-producing report — never wired into `evidence_class_for_rule`, the health score, or a baseline verdict.",
        exclusions: "Fast-Tier-reachable narrowing of the full todo.md §16.3 rule, deliberately without the full rule's consumer-side analysis: needs a `pub struct` with ≥2 `pub` fields and no `#[non_exhaustive]` attribute, plus at least one crate-local constructor-shaped `pub fn` (return type `Self`/the struct name, optionally `Result`-wrapped) that jointly validates ≥2 of those fields via matching parameter names. No cross-crate reasoning, no consumer call-site analysis.",
        allowed_wording: "Every claim must be phrased as an observation with checkable evidence locations, never an absolute claim (todo.md §16.7 'Sprachdisziplin'); never state this is 'the best' pattern or that the current structure is definitely wrong (todo.md §17.4). Always pair with a contraindication.",
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    RuleMetadata {
        id: "manual-resource-lifecycle",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires `cargo judge patterns` (or `explain-pattern`/`fix-preview`); not part of bare `cargo judge`, `audit`, or any Finding-producing report — never wired into `evidence_class_for_rule`, the health score, or a baseline verdict.",
        exclusions: "Fast-Tier-reachable narrowing of the full todo.md §16.3 rule, with no ownership/lifetime analysis: needs one function calling both an acquire-shaped operation and a release-shaped counterpart by call name alone, plus a crate with no `impl Drop for ...` anywhere. Cannot show that ownership and lifetime of the resource are actually bound to a single guard — acquire/release name matches can be coincidental and couple unrelated calls.",
        allowed_wording: "Every claim must be phrased as an observation with checkable evidence locations, never an absolute claim (todo.md §16.7 'Sprachdisziplin'); never state this is 'the best' pattern or that the current structure is definitely wrong (todo.md §17.4). Always pair with a contraindication.",
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    // -- provenance.rs ------------------------------------------------------
    RuleMetadata {
        id: "provenance-churn",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires git history with commit trailers/metadata; subcommand-only via `cargo judge provenance` — not part of bare `cargo judge`.",
        exclusions: "Commit trailers/markers are optional, unverified, and trivially fakeable; size/timing/style heuristics are weaker still.",
        allowed_wording: "Must always be shown together with `crate::provenance::PROVENANCE_CAVEAT`: a distribution trend, not a judgment on any single commit or person; never used to evaluate individual people or commits (todo.md §17.4, §3.G G6).",
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    RuleMetadata {
        id: "provenance-duplication-rate",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires git history with commit trailers/metadata; subcommand-only via `cargo judge provenance` — not part of bare `cargo judge`.",
        exclusions: "Commit trailers/markers are optional, unverified, and trivially fakeable; attribution is via blame, which is not a knowledge measurement.",
        allowed_wording: "Must always be shown together with `crate::provenance::PROVENANCE_CAVEAT`: a distribution trend, not a judgment on any single commit or person; never used to evaluate individual people or commits (todo.md §17.4, §3.G G6).",
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    RuleMetadata {
        id: "provenance-suppression-debt",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires git history with commit trailers/metadata; subcommand-only via `cargo judge provenance` — not part of bare `cargo judge`.",
        exclusions: "Commit trailers/markers are optional, unverified, and trivially fakeable; attribution is via blame, which is not a knowledge measurement.",
        allowed_wording: "Must always be shown together with `crate::provenance::PROVENANCE_CAVEAT`: a distribution trend, not a judgment on any single commit or person; never used to evaluate individual people or commits (todo.md §17.4, §3.G G6).",
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    RuleMetadata {
        id: "dep-added-by-agent",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires git history with commit trailers/metadata; subcommand-only via `cargo judge provenance` — not part of bare `cargo judge`.",
        exclusions: "Only checked for commits classified `AuthorClass::Agent` — the same fakeable trailer/marker/heuristic classification every other rule in this module relies on. The same-commit usage check is a plain substring scan (`use <ident>`, `<ident>::`, `extern crate <ident>`), not a `syn` parse — a `package = \"...\"` rename or a re-export under a different name reads as 'not referenced'. Target-specific dependency tables (`[target.'cfg(...)'.dependencies]`) are not read.",
        allowed_wording: "Must always be shown together with `crate::provenance::PROVENANCE_CAVEAT`: a distribution trend, not a judgment on any single commit or person; state only that the dependency was declared with no same-commit textual reference found — never that it 'was hallucinated' or 'is unused' (todo.md §17.4, §3.G G5/G6).",
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    // -- security.rs (Fast Tier security-shaped signals) -------------------
    RuleMetadata {
        id: "unsafe-surface",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`).",
        exclusions: "Scoped to `unsafe { .. }` expression blocks only — `unsafe fn`/`unsafe impl`/`unsafe trait` declarations are out of scope (a different existing convention: a `# Safety` doc section). The adjacency check for a `// SAFETY:` comment is a line-range heuristic (immediately preceding line, or the first inner line of the block) over `crate::slop_text`'s raw-source-text comment scan, not a semantic link between the comment and the block — a `SAFETY:` comment placed elsewhere (e.g. at the top of the enclosing function) is not credited.",
        allowed_wording: "State only that no `SAFETY:` comment was found adjacent to this unsafe block — never that the code is 'unsound' or 'a vulnerability' (todo.md §17.4).",
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "integer-cast-risk",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`).",
        exclusions: "A syntax-only proxy, not a truncation proof: true truncation detection needs the source expression's real type (a type checker), not available at the Fast Tier — the same limitation already documented for `silent-default`/`context-free-propagation` in `crate::slop`'s module doc. Only the cast's written target type is checked (`u8`/`i8`/`u16`/`i16`/`u32`/`i32`/`usize`/`isize`); false-positives on an already-narrow source (e.g. `byte_var as u8`), and false-negatives on a float cast to `u64`/`i64`/`u128`/`i128` (still narrowing, but not covered by this v1 target-type list).",
        allowed_wording: "State only that this is a possible truncation candidate based on the cast's target type — never 'this truncates' or 'this is a bug' (todo.md §17.4).",
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    RuleMetadata {
        id: "panic-in-lib",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`).",
        exclusions: "Scoped to a function whose own written visibility is `pub` — item-level only, same simplification as `undocumented-public-item` (a `pub fn` inside a private `mod` is still checked as if reachable; a trait default method, with no visibility of its own, is never checked). `.unwrap()`/`.expect(..)`/indexing are name/operator matches, not resolved against a real `Option`/`Result`/`Index` type — a type defining its own non-panicking method or operator of the same name is not distinguished from the standard, panicking one (same accepted imprecision as `swallowed-result`'s `.ok()` match). Does not distinguish a `[lib]` target's public API from a `[[bin]]`-only crate's `pub` items, which are never actually reachable by another crate. `#[test]`-attributed functions are excluded directly; a `#[cfg(test)] mod tests {..}` block is not tracked, but its functions are almost never themselves `pub`.",
        allowed_wording: "State only that a panic-shaped construct (`.unwrap()`/`.expect(..)`/`panic!(..)`/indexing) exists on a `pub` path — never that it 'will panic', 'crashes', or 'is a bug' (todo.md §17.4).",
        verdict_effect: VerdictEffect::Gating,
        example: Some(RuleExample {
            before: "pub fn read_config(raw: Option<&str>) -> &str {\n    raw.unwrap()\n}\n",
            why_it_matters: "A public function that unwraps its input hands every caller a landmine: a missing config value doesn't return an error — it takes down the whole program.",
        }),
    },
    RuleMetadata {
        id: "hardcoded-secret",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`).",
        exclusions: "Two lanes (`evidence.kind`): `known_pattern` matches a string literal against a small, publicly documented list of secret-provider formats (AWS/GitHub/Slack/Google, PEM headers) anywhere in the file — a provider's own documented example value (e.g. AWS's `AKIAIOSFODNN7EXAMPLE`) matches identically to a live key. `high_entropy_assignment` requires a string literal to be the direct initializer of a `let`/`const`/`static` whose own name contains a suspicious marker, plus a minimum length and Shannon entropy — ordinary high-entropy strings (hashes, UUIDs, encoded blobs) are not flagged unless bound to such a name, but a placeholder/rotated/revoked credential is indistinguishable from a live one either way. `#[test]`-attributed functions and `#[cfg(test)]`-gated items are excluded from both lanes. `evidence` never includes the literal's own text, only its kind/pattern/length.",
        allowed_wording: "State only that a string literal matches a known secret-provider format, or is bound to a suspiciously-named binding with high entropy — never that it 'is a secret', 'is leaked', or 'is a vulnerability' (todo.md §17.4).",
        verdict_effect: VerdictEffect::AdvisoryOnly,
        // Deliberately NOT a real provider's key shape (e.g. Google's `AIza`
        // + 39 chars) — a byte-for-byte match would trip GitHub's own
        // secret scanning on this very file. This demonstrates the entropy
        // lane instead: a suspiciously-named binding plus a high-entropy,
        // non-provider-shaped literal.
        example: Some(RuleExample {
            before: "const API_SECRET: &str = \"Kx7$mQ2#Lp9@Rn4^Wz6&Tb3!\";\n",
            why_it_matters: "A credential committed as a literal ends up in git history forever, readable by anyone with clone access, long after it's rotated out of the running config.",
        }),
    },
    // -- slop.rs (G1 error-masking, G2 stub/theater-code, G3 lexical) -------
    RuleMetadata {
        id: "swallowed-result",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Syntax-only: only `let _ = fallible();` and a bare `.ok();` statement are matched; other ways of discarding a `Result` are not.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: Some(RuleExample {
            before: "fn save_settings(path: &std::path::Path, data: &str) {\n    let _ = std::fs::write(path, data);\n}\n",
            why_it_matters: "Discarding a `Result` with `let _ = ...` throws away the one signal that the operation could fail — a failed disk write here looks exactly like a successful save to every caller downstream.",
        }),
    },
    RuleMetadata {
        id: "empty-error-arm",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only an empty `Err(_)`/`Err(..)` match arm, or an `if let Err(_) = ... { }` with no `else`, is matched.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "catch-all-error",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only `pub fn` boundaries whose error type is erased (`Box<dyn Error>` / `anyhow::Error`) are matched; internal (non-`pub`) error erasure is out of scope.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "suppression-debt",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block). Reported as `Severity::Info` for the current state only — trend-against-baseline is handled by the existing baseline/delta system.",
        exclusions: "Counts `#[allow(...)]`/`#[expect(...)]` attribute occurrences; does not judge whether any individual suppression is justified.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "merged-stub",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only bare `todo!()`/`unimplemented!()` outside a `#[cfg(feature = ...)]`-gated scope; feature-gated stubs are excluded by design.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "empty-impl",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only a function/method/trait-default with a doc comment and a literally empty body is matched; an empty body without a doc comment is not flagged.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "assertion-free-test",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only the literal `#[test]` attribute (without `#[should_panic]`) is matched, not third-party test-framework attributes (`#[tokio::test]`, `#[rstest]`, ...). Syntactically assertion-free does not mean the test is ineffective — macros, propagated return errors, and helper functions can still exercise behavior.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "tautological-test",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only the literal `assert!(true)` / `assert_eq!(x, x)` shapes are matched.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "ignored-test-accumulation",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block). Reported as `Severity::Info` for the current state only — trend-against-baseline is handled by the existing baseline/delta system.",
        exclusions: "Only the literal `#[ignore]`/`#[ignore = \"...\"]` attribute is matched, not third-party test-framework equivalents.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "conversational-artifact",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only plain `//`/`/* */` comments are scanned (raw source-text scan in `crate::slop_text`, since `syn` discards non-doc comments entirely); `///`/`//!` doc comments are out of scope for this rule.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "restating-comment",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only plain `//`/`/* */` comments are scanned (raw source-text scan in `crate::slop_text`); `///`/`//!` doc comments are out of scope for this rule (see `doc-restates-signature`).",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "step-comment-inflation",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only plain `//`/`/* */` comments are scanned (raw source-text scan in `crate::slop_text`); requires a chain of three or more `// Step N:`-shaped comments.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "generic-naming",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only an identifier that is exactly a fixed placeholder word (`data`, `temp`, `handler`, ...) is flagged; a poorly named identifier outside that list is not.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "doc-restates-signature",
        evidence_class: EvidenceClass::DerivedFact,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only a doc comment that is a pure signature echo is flagged; a doc comment that adds any information beyond the signature is not.",
        allowed_wording: DERIVED_FACT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    // -- slop_structural.rs (G4, Fast Tier subset) ---------------------------
    RuleMetadata {
        id: "churn-hotspot",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier, needs git history; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "14-day window, first-cut commit-count threshold; a file rewritten for legitimate reasons (e.g. a planned refactor) scores the same as unplanned rework.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    RuleMetadata {
        id: "complexity-inflation",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Flags a long function with implausibly low branching; does not distinguish a genuinely simple long function (e.g. a large match/data table) from a padded one.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    RuleMetadata {
        id: "legacy-freeze",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier, needs git history; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "12-month window; a file that is stable because it is finished looks identical to one that is stale/abandoned.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    RuleMetadata {
        id: "abstraction-inflation",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Covers three sub-patterns (single-impl trait, delegating wrapper, builder for a small struct) via `evidence.kind`; a deliberate abstraction seam kept for testability/future extension looks structurally identical to an unnecessary one.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    RuleMetadata {
        id: "fragile-substring-classification",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier; part of bare `cargo judge`, `audit`, and `health`'s slop block).",
        exclusions: "Only if/else-if chains of 2+ conditions are considered, and a condition is only flagged for a missing word-boundary check within that same condition expression; whether the string literal ever actually collides with an unrelated substring in real input is not evaluated — a shape-based hint, not a misclassification proof.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    // -- slop_structural_deep.rs (G4 remainder, Deep Tier, `--features deep`)
    RuleMetadata {
        id: "duplicative-reinvention",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires `--features deep` and `cargo judge dead-code` (Deep Tier; needs `find_all_refs` cross-file reference data). Reported as `Severity::Info` for the current state only — trend-against-baseline is handled by the existing baseline/delta system.",
        exclusions: "Test/bench-attributed functions and methods inside `impl TraitName for SomeType` blocks are excluded from the candidate set entirely, not down-weighted — trait-impl methods are routinely invoked through operator/macro sugar `find_all_refs` can't see (e.g. `Display::fmt`, `Iterator::next`, `Drop::drop`), so they would otherwise look structurally unwired even when used everywhere.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    RuleMetadata {
        id: "connectivity-drop",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Requires `--features deep` and `cargo judge dead-code` (Deep Tier; needs `find_all_refs` cross-file reference data). Reported as `Severity::Info` for the current state only — trend-against-baseline is handled by the existing baseline/delta system.",
        exclusions: "Test/bench-attributed functions and methods inside `impl TraitName for SomeType` blocks are excluded from the candidate set entirely, not down-weighted — trait-impl methods are routinely invoked through operator/macro sugar `find_all_refs` can't see (e.g. `Display::fmt`, `Iterator::next`, `Drop::drop`), so they would otherwise look structurally unwired even when used everywhere.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    // -- slopsquat.rs (G5) ----------------------------------------------------
    RuleMetadata {
        id: "name-collision-risk",
        evidence_class: EvidenceClass::Heuristic,
        preconditions: "Always evaluated (Fast Tier, fully local/offline; part of bare `cargo judge`, `audit`, and `cargo judge deps`).",
        exclusions: "Levenshtein-distance match against a manually curated, potentially stale static list of well-known crates (`data/popular_crates.txt`); neither exhaustive nor auto-updated.",
        allowed_wording: HEURISTIC_WORDING,
        verdict_effect: VerdictEffect::AdvisoryOnly,
        example: None,
    },
    RuleMetadata {
        id: "phantom-crate",
        evidence_class: EvidenceClass::ExternalMeasurement,
        preconditions: "Requires `cargo judge deps --check-crates-io` (opt-in network access to the crates.io sparse index).",
        exclusions: "A snapshot at lookup time — a crate published moments after the check ran is indistinguishable from one that never existed.",
        allowed_wording: EXTERNAL_MEASUREMENT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "phantom-version",
        evidence_class: EvidenceClass::ExternalMeasurement,
        preconditions: "Requires `cargo judge deps --check-crates-io` (opt-in network access to the crates.io sparse index).",
        exclusions: "A snapshot at lookup time — a matching version published or un-yanked moments after the check ran is indistinguishable from one that never existed.",
        allowed_wording: EXTERNAL_MEASUREMENT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "fresh-low-reputation-dep",
        evidence_class: EvidenceClass::ExternalMeasurement,
        preconditions: "Requires `cargo judge deps --check-crates-io` (opt-in network access to the crates.io REST API).",
        exclusions: "Download counts and repository-link presence are the crates.io REST API's own signals, not something judge independently verifies; a snapshot at lookup time.",
        allowed_wording: EXTERNAL_MEASUREMENT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "yanked-dependency",
        evidence_class: EvidenceClass::ExternalMeasurement,
        preconditions: "Requires `cargo judge deps --check-crates-io` (opt-in network access to the crates.io sparse index). Runs its own full, non-`--no-deps` `cargo metadata` resolve to see actual resolved versions, not just declared requirements — see `crate::slopsquat::analyze_yanked_dependencies`.",
        exclusions: "Checked against every resolved, non-workspace-member package (direct and transitive), not just directly declared dependencies — distinct from `phantom-version`, which checks whether the declared *requirement* has any non-yanked satisfying version at all. A snapshot at lookup time — a publisher un-yanking a version moments after the check ran is indistinguishable from one that was never yanked.",
        allowed_wording: EXTERNAL_MEASUREMENT_WORDING,
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "dep-single-maintainer",
        evidence_class: EvidenceClass::ExternalMeasurement,
        preconditions: "Requires `cargo judge deps --check-crates-io` (opt-in network access to the crates.io REST owners endpoint).",
        exclusions: "Checked against directly declared dependencies only, not the full resolved graph (unlike `yanked-dependency`) — a transitive dependency's own maintainer count is not checked. A raw crates.io owner count (`< 2` fires), with no insight into each owner's actual activity — two owners who are both inactive score the same as two active ones; a snapshot at lookup time.",
        allowed_wording: "State only the owner count and login names crates.io reports — never that the crate is 'abandoned', 'unmaintained', or 'risky' (todo.md §17.4).",
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
    RuleMetadata {
        id: "known-vulnerability",
        evidence_class: EvidenceClass::ExternalMeasurement,
        preconditions: "Requires `cargo judge deps --audit-json PATH`, an already-generated `cargo audit --json` report (opt-in; judge never runs `cargo-audit` itself). Runs its own full, non-`--no-deps` `cargo metadata` resolve to cross-reference reachability — see `crate::advisories` module docs.",
        exclusions: "Reachability is a dependency-graph classification (`production`/`dev_only`/`unknown` in `evidence.reachability`), not a call-graph one — RUSTSEC advisories are scoped to crate+version, not specific functions, so there is no function-level target for the Deep Tier `--why-live` engine to check. `production` is `Severity::Fail`; `dev_only`/`unknown` are `Severity::Warn` — never silently dropped, just not asserted with `Fail`-level confidence. A package/version cargo-audit reported that judge's own resolve doesn't find at all (a stale report, or a workspace-root mismatch) is `unknown`, still reported. Only `cargo audit --json`'s format is imported; `cargo deny --format json` is not.",
        allowed_wording: "State only the advisory id, the reachability classification, and its basis — never that the crate is 'exploited' or 'unsafe to use' beyond what the advisory itself claims (todo.md §17.4).",
        verdict_effect: VerdictEffect::Gating,
        example: None,
    },
];

/// Looks up one rule's fixed documentation by id. `None` for an id not in
/// [`RULE_REGISTRY`] — the CLI turns that into a usage error, not a panic.
pub fn lookup(rule_id: &str) -> Option<&'static RuleMetadata> {
    RULE_REGISTRY.iter().find(|entry| entry.id == rule_id)
}

/// Rule ids with no curated `example` yet, and why — every entry in
/// [`RULE_REGISTRY`] must either set `example: Some(_)` or be listed here
/// with a documented reason (see the completeness test below). This is what
/// keeps a curated example from being an optional afterthought that quietly
/// never happens: a newly added rule id with neither an example nor an
/// exemption fails `cargo test`. See
/// `.claude/skills/curate-rule-example/SKILL.md` for how to add one, and add
/// a new rule id here — with a real reason, not a placeholder — only when a
/// single self-contained snippet genuinely cannot trigger it (needs
/// `judge.toml` config, real git commit history, a network-backed
/// crates.io lookup's own resolved-graph shape, an externally imported
/// report, or an expensive full-workspace compile).
const NO_EXAMPLE_YET: &[(&str, &str)] = &[
    (
        "crate-boundary-violation",
        "needs a multi-crate workspace plus a judge.toml [[boundary]]/[layers] config, not a single source snippet",
    ),
    (
        "dependency-cycle",
        "needs a multi-crate workspace plus a judge.toml [[boundary]]/[layers] config",
    ),
    (
        "change-coupling-signal",
        "needs a judge.toml [layers] config plus real git co-change history across commits — not expressible as a single source snippet",
    ),
    (
        "module-boundary-violation",
        "needs a multi-crate workspace plus a judge.toml [[module_boundary]] config",
    ),
    (
        "internal-leak",
        "needs --features deep plus a judge.toml internal_crates config plus a multi-crate workspace",
    ),
    (
        "module-boundary-violation-deep",
        "needs --features deep plus a judge.toml [[module_boundary]] config",
    ),
    (
        "untested-hotspot",
        "needs an externally generated cargo-llvm-cov LCOV report import — judge never measures coverage itself",
    ),
    (
        "unused-dependency",
        "opt-in --check-rustc-lints; triggering it for real needs a full `cargo check --workspace --all-targets` compile, too expensive for an illustrative snippet",
    ),
    (
        "hotspot",
        "needs real git commit history (churn) — not expressible as a single source snippet",
    ),
    (
        "low-bus-factor",
        "needs real git commit history with at least 2 distinct authors",
    ),
    (
        "ownership-fragmentation",
        "needs real git blame history across at least 4 authors",
    ),
    (
        "provenance-churn",
        "needs real git commit history with trailers/metadata",
    ),
    (
        "provenance-duplication-rate",
        "needs real git commit history with trailers/metadata",
    ),
    (
        "provenance-suppression-debt",
        "needs real git commit history with trailers/metadata",
    ),
    (
        "dep-added-by-agent",
        "needs a real git commit (trailer-classified as agent-authored) that also changed Cargo.toml",
    ),
    (
        "churn-hotspot",
        "needs real git commit history (14-day window)",
    ),
    (
        "legacy-freeze",
        "needs real git commit history (12-month window)",
    ),
];

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
            crate::api_surface::UNDOCUMENTED_PUBLIC_ITEM_RULE,
            crate::api_surface::SEMVER_HAZARD_RULE,
            crate::boundaries::BOUNDARY_VIOLATION_RULE,
            crate::boundaries::DEPENDENCY_CYCLE_RULE,
            crate::boundaries::MODULE_BOUNDARY_VIOLATION_RULE,
            crate::boundaries::FEATURE_GRAPH_CYCLE_RULE,
            crate::boundaries::CHANGE_COUPLING_SIGNAL_RULE,
            crate::coverage::UNTESTED_HOTSPOT_RULE,
            crate::dep_graph::DUPLICATE_CRATE_VERSIONS_RULE,
            crate::dep_graph::MSRV_DRIFT_RULE,
            crate::dep_graph::WORKSPACE_DEP_DRIFT_RULE,
            crate::deps::MISPLACED_DEPENDENCY_KIND_RULE,
            crate::deps::UNUSED_DEV_DEPENDENCY_RULE,
            crate::deps::HEAVY_DEPENDENCY_RULE,
            crate::deps::UNUSED_FEATURE_FLAG_RULE,
            crate::deps::DEFAULT_FEATURES_UNUSED_RULE,
            crate::deps::UNUSED_FEATURE_RULE,
            crate::deps::UNUSED_DEPENDENCY_RULE,
            crate::deps::DEP_WITHOUT_REPO_RULE,
            crate::duplication::DUPLICATE_RULE,
            crate::git::HOTSPOT_RULE,
            crate::git::SIZE_DISTRIBUTION_RULE,
            crate::module_graph::UNLINKED_FILE_RULE,
            crate::module_graph::ORPHAN_MODULE_RULE,
            crate::ownership::LOW_BUS_FACTOR_RULE,
            crate::ownership::OWNERSHIP_FRAGMENTATION_RULE,
            crate::pattern::STRINGLY_ERROR_BOUNDARY_RULE,
            crate::pattern::PRIMITIVE_DOMAIN_VALUE_RULE,
            crate::pattern::BOOLEAN_STATE_CLUSTER_RULE,
            crate::pattern::PUBLIC_INVARIANT_BYPASS_RULE,
            crate::pattern::MANUAL_RESOURCE_LIFECYCLE_RULE,
            crate::provenance::PROVENANCE_CHURN_RULE,
            crate::provenance::PROVENANCE_DUPLICATION_RATE_RULE,
            crate::provenance::PROVENANCE_SUPPRESSION_DEBT_RULE,
            crate::provenance::DEP_ADDED_BY_AGENT_RULE,
            crate::security::UNSAFE_SURFACE_RULE,
            crate::security::INTEGER_CAST_RISK_RULE,
            crate::security::PANIC_IN_LIB_RULE,
            crate::security::HARDCODED_SECRET_RULE,
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
            crate::slop_structural::FRAGILE_SUBSTRING_CLASSIFICATION_RULE,
            crate::slopsquat::NAME_COLLISION_RISK_RULE,
            crate::slopsquat::PHANTOM_CRATE_RULE,
            crate::slopsquat::PHANTOM_VERSION_RULE,
            crate::slopsquat::FRESH_LOW_REPUTATION_DEP_RULE,
            crate::slopsquat::YANKED_DEPENDENCY_RULE,
            crate::slopsquat::DEP_SINGLE_MAINTAINER_RULE,
            crate::advisories::KNOWN_VULNERABILITY_RULE,
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
            crate::dead_code::UNUSED_PUB_API_RULE,
            crate::dead_code::DEAD_ENUM_VARIANT_RULE,
            crate::dead_code::TEST_ONLY_PUB_RULE,
            crate::slop_structural_deep::DUPLICATIVE_REINVENTION_RULE,
            crate::slop_structural_deep::CONNECTIVITY_DROP_RULE,
            crate::api_surface_deep::INTERNAL_LEAK_RULE,
            crate::api_surface_deep::RE_EXPORT_CHAIN_RULE,
            crate::boundaries_deep::MODULE_BOUNDARY_VIOLATION_DEEP_RULE,
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

    /// Every registry entry has a curated `example` or a documented
    /// exemption in [`NO_EXAMPLE_YET`] — see that constant's doc comment.
    /// This is the enforcement mechanism: a newly added rule with neither
    /// fails here, so a curated example can't be silently forgotten.
    #[test]
    fn every_registry_entry_has_an_example_or_a_documented_exemption() {
        for entry in RULE_REGISTRY {
            if entry.example.is_none() {
                assert!(
                    NO_EXAMPLE_YET.iter().any(|(id, _)| *id == entry.id),
                    "rule `{}` has no curated `example` and no documented exemption in \
                     NO_EXAMPLE_YET — add a RuleExample (see \
                     .claude/skills/curate-rule-example/SKILL.md) or add a reasoned \
                     exemption entry",
                    entry.id
                );
            }
        }
    }

    /// Every [`NO_EXAMPLE_YET`] id is a real, still-exampleless registry
    /// entry — a stale/misspelled exemption would silently stop being
    /// checked, and a rule that later gains an example should have its
    /// exemption removed, not left to accumulate.
    #[test]
    fn every_exemption_is_a_real_rule_id_still_missing_an_example() {
        for (id, reason) in NO_EXAMPLE_YET {
            assert!(!reason.is_empty(), "exemption `{id}` has an empty reason");
            let entry =
                lookup(id).unwrap_or_else(|| panic!("exemption `{id}` is not a real rule id"));
            assert!(
                entry.example.is_none(),
                "rule `{id}` is listed in NO_EXAMPLE_YET but already has a curated example — remove the stale exemption"
            );
        }
    }
}
