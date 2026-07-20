//! The common output unit for detectors: a `Finding`. Findings can reference
//! each other (`caused_by`/`causes`) so a single root cause — e.g. a missed
//! entry point — doesn't present as dozens of unrelated findings (see
//! todo.md §7 "Kausale Finding-Gruppen", §14.2 P0#1). Causal edges are owned
//! exclusively by [`FindingGraph`] (todo.md §15.2): detectors emit findings
//! without edges, the graph stores each edge once, and the per-finding
//! `caused_by`/`causes` fields are derived from that single edge set on
//! export.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Stable identifier for a finding, referenced by `caused_by`/`causes` links.
/// A newtype around the existing id string (e.g. `hotspot:src/lib.rs`) — the
/// id computation is unchanged, the type only makes graph indexing explicit.
/// Serializes transparently as that string, so the JSON schema is unaffected.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FindingId(String);

impl FindingId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for FindingId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for FindingId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl std::fmt::Display for FindingId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for FindingId {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for FindingId {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// Stable identifier of a rule (e.g. `duplicate-code`). A newtype around the
/// rule-id string each detector exposes as a `&'static str` constant — the
/// ids themselves are unchanged, and `#[serde(transparent)]` keeps the JSON
/// schema (and every baseline) byte-identical to the former plain string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RuleId(String);

impl RuleId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for RuleId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for RuleId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl std::fmt::Display for RuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for RuleId {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for RuleId {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// Ordered `Info < Warn < Fail` (derive order follows declaration order) so
/// findings can be sorted worst-first across detectors — see
/// [`sort_by_severity_desc`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warn,
    Fail,
}

/// How a finding's claim is backed — the categorical replacement for the
/// former numeric `confidence` score (todo.md §17.2, §17.5: numbers like
/// `0.95` suggest a calibrated probability that never existed).
///
/// Rule → class mapping (see [`evidence_class_for_rule`], todo.md §17.3):
///
/// | Rule | Class |
/// |---|---|
/// | `swallowed-result`, `empty-error-arm`, `catch-all-error`, `suppression-debt`, `merged-stub`, `empty-impl`, `assertion-free-test`, `tautological-test`, `ignored-test-accumulation`, `conversational-artifact`, `restating-comment`, `step-comment-inflation`, `generic-naming`, `doc-restates-signature` | `derived_fact` (G1–G3: the reported pattern is a syntax fact) |
/// | `undocumented-public-item` | `derived_fact` (the absence of a `#[doc = ...]` attribute on a `pub` item is an exact syntax fact — see `crate::api_surface`) |
/// | `semver-hazard` | `derived_fact` (the absence of a `#[non_exhaustive]` attribute on a `pub enum`/`pub struct` is an exact syntax fact — see `crate::api_surface`) |
/// | `duplicate-code` | `derived_fact` for `Strict`/`Mild` token equality; `heuristic` for `Weak`/`Semantic` normalization (see [`crate::duplication::CloneMember::to_finding`]) |
/// | `duplicate-crate-versions`, `msrv-drift`, `workspace-dep-drift` | `derived_fact` (manifest/resolve-graph facts read directly from `cargo_metadata`) |
/// | `unused-feature-flag` | `derived_fact` (the feature is declared in the manifest, and zero usage of the dependency was found anywhere in the examined view — both read directly from the declared inputs, see [`crate::deps`] module docs "Feature-only evidence") |
/// | `default-features-unused` | `derived_fact` (the manifest text explicitly sets `default-features = true`, and zero usage of the dependency was found anywhere in the examined view — see [`crate::deps`] module docs "Feature-only evidence") |
/// | `unused-pub-workspace`, `crate-boundary-violation`, `dependency-cycle` | `bounded_semantic` (proven only within the loaded workspace / configured crate graph) |
/// | `module-boundary-violation` | `bounded_semantic` (an explicitly configured edge over a heuristically derived, directory-convention module view — see [`crate::boundaries`] module docs "Module-level boundaries") |
/// | `unused-dev-dependency` | `bounded_semantic` (no usage found in the examined view — tests/examples/benches and `#[cfg(test)]` modules of the declaring package; doctests are not scanned) |
/// | `unused-dependency` | `bounded_semantic` (rustc's own `unused_crate_dependencies` lint result, narrowed to the intersection across every target compiled for the package — see [`crate::deps`] module docs "Importing rustc's `unused_crate_dependencies` lint") |
/// | `phantom-crate`, `phantom-version`, `fresh-low-reputation-dep` | `external_measurement` (a crates.io lookup snapshot) |
/// | `untested-hotspot` | `external_measurement` (complexity and churn are `derived_fact`/`heuristic` in isolation, but the imported `cargo-llvm-cov` coverage snapshot is the rarest, least locally-verifiable ingredient in the combination, so it sets the class — see `crate::coverage::untested_hotspots`) |
/// | `hotspot`, `churn-hotspot`, `low-bus-factor`, `ownership-fragmentation`, `abstraction-inflation`, `complexity-inflation`, `legacy-freeze`, `duplicative-reinvention`, `connectivity-drop`, `name-collision-risk`, `misplaced-dependency-kind`, `heavy-dependency`, `provenance-churn`, `provenance-duplication-rate`, `provenance-suppression-debt` | `heuristic` (reproducible interpretation, not proof) |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    /// Exactly derived from the declared inputs — syntax facts, strict/mild
    /// token duplicates, manifest facts, suppressions (todo.md §17.2).
    DerivedFact,
    /// Semantically backed, but only within a fully described analysis view —
    /// e.g. "no reference found in the loaded workspace for the searched
    /// crates/entry points" (todo.md §17.2).
    BoundedSemantic,
    /// The result of a concrete external run/snapshot — e.g. a crates.io
    /// index/API query. Valid for that snapshot, not a timeless truth
    /// (todo.md §17.2).
    ExternalMeasurement,
    /// A reproducible interpretation of facts/measurements — a hint by
    /// default, never proof (todo.md §17.2).
    Heuristic,
}

impl EvidenceClass {
    /// Whether findings of this class may affect a verdict/exit code or the
    /// health score. [`EvidenceClass::Heuristic`] findings are advisory by
    /// default — reported, but never gating (todo.md §17.2: "standardmäßig
    /// nur Hinweis, kein Exitcode 1"). The single place this policy lives;
    /// every verdict/score consumer goes through it.
    pub const fn is_gating(self) -> bool {
        !matches!(self, Self::Heuristic)
    }
}

/// The single authoritative rule-id → [`EvidenceClass`] mapping (see the
/// table on [`EvidenceClass`]). Used by detectors whose constructors take a
/// rule id, and by the baseline v1→v2 migration, which must derive a class
/// from nothing but the stored rule id.
///
/// `duplicate-code` maps to its `Strict`/`Mild` (default-mode, fact-backed)
/// class here; `Weak`/`Semantic` creation sites override to `Heuristic` at
/// the source (see [`crate::duplication::CloneMember::to_finding`]) — a
/// migrated v1 baseline entry can't recover the mode, and baseline entries
/// only serve identity matching. Unknown rule ids (e.g. from a v1 baseline
/// written by a different judge) conservatively map to `Heuristic`.
/// `pub(crate)`: only detectors and the baseline migration consult the
/// mapping — consumers read the materialized `Finding.evidence_class`.
pub(crate) fn evidence_class_for_rule(rule: &RuleId) -> EvidenceClass {
    match rule.as_str() {
        "swallowed-result"
        | "empty-error-arm"
        | "catch-all-error"
        | "suppression-debt"
        | "merged-stub"
        | "empty-impl"
        | "assertion-free-test"
        | "tautological-test"
        | "ignored-test-accumulation"
        | "conversational-artifact"
        | "restating-comment"
        | "step-comment-inflation"
        | "generic-naming"
        | "doc-restates-signature"
        | "undocumented-public-item"
        | "semver-hazard"
        | "duplicate-code"
        | "duplicate-crate-versions"
        | "msrv-drift"
        | "workspace-dep-drift" => EvidenceClass::DerivedFact,
        "unused-feature-flag" => EvidenceClass::DerivedFact,
        "default-features-unused" => EvidenceClass::DerivedFact,
        "unused-pub-workspace"
        | "crate-boundary-violation"
        | "dependency-cycle"
        | "module-boundary-violation"
        | "unused-dev-dependency"
        | "unused-dependency" => EvidenceClass::BoundedSemantic,
        "phantom-crate" | "phantom-version" | "fresh-low-reputation-dep" | "untested-hotspot" => {
            EvidenceClass::ExternalMeasurement
        }
        _ => EvidenceClass::Heuristic,
    }
}

/// Where a finding comes from. Distinguishes an actual code issue from a
/// finding about judge's own configuration or analyzer state, which must
/// not be suppressed or baselined the same way (see todo.md §14.2 P0#1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Code,
    Config,
    Analyzer,
}

/// A 1-based source line number. Line 0 is unrepresentable: every producer
/// (syn/proc-macro2 spans, git blame, manual "whole file" anchors) counts
/// from 1, and the fallible constructor makes that invariant a type instead
/// of a convention. Serializes as the bare number — the JSON schema is
/// unchanged — while deserialization validates via `TryFrom` and rejects 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "usize", try_from = "usize")]
pub struct OneBasedLine(usize);

impl OneBasedLine {
    /// The first line of a file — the anchor for findings about a file (or
    /// manifest) as a whole rather than a specific line.
    pub const FIRST: Self = Self(1);

    pub fn new(line: usize) -> Option<Self> {
        (line != 0).then_some(Self(line))
    }

    pub fn get(self) -> usize {
        self.0
    }
}

impl From<OneBasedLine> for usize {
    fn from(value: OneBasedLine) -> Self {
        value.0
    }
}

impl TryFrom<usize> for OneBasedLine {
    type Error = &'static str;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::new(value).ok_or("line numbers are 1-based; 0 is not a valid line")
    }
}

impl PartialEq<usize> for OneBasedLine {
    fn eq(&self, other: &usize) -> bool {
        self.0 == *other
    }
}

impl std::fmt::Display for OneBasedLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Location {
    pub file: PathBuf,
    pub line: OneBasedLine,
    pub item_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Stable identifier (e.g. `hotspot:src/lib.rs`) — the same [`FindingId`]
    /// the causal edges reference. Detectors build the underlying string
    /// inline; [`relativize_paths`] rebases it together with `location`.
    pub id: FindingId,
    pub rule: RuleId,
    pub severity: Severity,
    pub location: Location,
    pub evidence_class: EvidenceClass,
    pub origin: Origin,
    /// Free-form, rule-specific proof for why this finding fired — e.g. how
    /// many crates/entry points were searched, and what backs
    /// `evidence_class` (see todo.md §7). `None` where a detector doesn't
    /// yet populate it; not every rule does.
    pub evidence: Option<serde_json::Value>,
    /// Findings that caused this one to appear (the root-cause direction).
    /// Derived from [`FindingGraph`]'s edge set on export — `pub(crate)` so
    /// the public API cannot set it independently of `causes` (todo.md
    /// §15.2: one stored truth, the reverse direction is derived).
    pub(crate) caused_by: Vec<FindingId>,
    /// Findings this one caused to appear (the cascade direction). Same
    /// ownership rule as `caused_by`: only [`FindingGraph`] populates it.
    pub(crate) causes: Vec<FindingId>,
}

impl Finding {
    /// Constructs a finding without causal edges — the only way to attach
    /// edges is [`FindingGraph::add_edge`], which validates ids, duplicates,
    /// and cycles.
    pub fn new(
        id: impl Into<FindingId>,
        rule: impl Into<RuleId>,
        severity: Severity,
        location: Location,
        evidence_class: EvidenceClass,
        origin: Origin,
        evidence: Option<serde_json::Value>,
    ) -> Self {
        Self {
            id: id.into(),
            rule: rule.into(),
            severity,
            location,
            evidence_class,
            origin,
            evidence,
            caused_by: Vec::new(),
            causes: Vec::new(),
        }
    }

    /// See [`EvidenceClass::is_gating`] — `false` means this finding is
    /// advisory: shown, but with no effect on verdicts or the health score.
    pub fn is_gating(&self) -> bool {
        self.evidence_class.is_gating()
    }

    /// Findings that caused this one (read-only; derived from
    /// [`FindingGraph`]'s edge set on export).
    pub fn caused_by(&self) -> &[FindingId] {
        &self.caused_by
    }

    /// Findings this one caused (read-only; derived from
    /// [`FindingGraph`]'s edge set on export).
    pub fn causes(&self) -> &[FindingId] {
        &self.causes
    }
}

/// Current version of the JSON report schema (see todo.md §7). Bump whenever
/// a field is removed or changes meaning; additive fields don't require it.
/// v2: `Finding.confidence: f32` replaced by `Finding.evidence_class`
/// (todo.md §17.5).
pub const SCHEMA_VERSION: u32 = 2;

/// Tri-state status of an analysis capability, so a tier where a capability
/// has no meaning at all doesn't have to report a false `true`/`false`: the
/// Fast Tier is a syntactic pass that never expands anything, and
/// `proc_macro_expansion: false` there would read like a Deep-Tier-style
/// fidelity trade-off instead of "no such dimension exists here"
/// (todo.md §17.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FidelityStatus {
    /// The capability was active during analysis.
    Enabled,
    /// The capability exists for this tier but was deliberately off — a
    /// real, documented fidelity trade-off (e.g. the Deep Tier loads without
    /// a proc-macro server and without running build scripts; see
    /// `judge::deep`'s `DeepContext::load`).
    Disabled,
    /// The capability has no meaning for this tier — nothing was traded off.
    NotApplicable,
}

/// What the analysis actually looked at — the report-level answer to "what
/// is this report even a claim about?" (todo.md §17.5, §0): source snapshot,
/// examined targets, feature selection, platform, entry-point model, test
/// and generated-code policy, expansion fidelity, and the judge version.
///
/// Lives on [`Report`], not on each [`Finding`]: one report is one analysis
/// view, and repeating the universe per finding (as todo.md §7's schema
/// sketch shows) would be massively redundant. Should a future detector ever
/// produce findings under a *different* view than the enclosing report's
/// (none does today), a per-finding override would be follow-up work — not
/// part of this type.
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisUniverse {
    /// Full hex object id of `HEAD` at analysis time — the source snapshot
    /// the claims are about. `None` outside a git repository (or when the
    /// workspace root is not itself the repository root, matching how
    /// `crate::git` opens repositories everywhere else).
    pub commit: Option<String>,
    /// Cargo target kinds discovered in the workspace, deduped and sorted —
    /// the ingest layer's labels: `lib`, `bin`, `example`, `test`, `bench`,
    /// `build-script` (see `crate::ingest::EntryPointKind::label`).
    pub targets: Vec<String>,
    /// The cargo feature selection the analyzed view was resolved under.
    /// Deep Tier: `["all"]` — `DeepContext::load` (`crate::deep`) loads the
    /// workspace with every feature active (`CargoFeatures::All`,
    /// `--all-features`-equivalent), not just `default`. Fast Tier: empty —
    /// the syntactic pass is feature-blind and parses every `cfg`-gated line
    /// regardless of any selection.
    pub features: Vec<String>,
    /// Host platform the analysis ran on, as `<arch>-<os>` from
    /// `std::env::consts`.
    pub platform: String,
    /// Entry-point kinds the reachability root set recognizes (see
    /// `crate::reachability`): `fn-main-bin`, `fn-main-example`, `test` and
    /// `bench` only with `--include-tests`, plus `no-mangle`, `export-name`,
    /// `wasm-bindgen` unconditionally. Empty at the Fast Tier, which makes
    /// no reachability claims and therefore has no entry-point model.
    pub entry_points: Vec<String>,
    /// Whether test code counted as usage/entry points (`--include-tests`).
    /// Always `true` at the Fast Tier: its test-focused rules
    /// (assertion-free-test, tautological-test, …) require parsing test
    /// code, so tests are always part of the examined universe there.
    pub include_tests: bool,
    /// Whether generated files were analyzed as finding targets
    /// (`--include-generated`). Generated code stays part of the graph
    /// either way (see `crate::ingest::SourceKind`) — this only says whether
    /// findings were reported *about* it.
    pub include_generated: bool,
    /// Whether proc-macros were expanded. [`FidelityStatus::Disabled`] at
    /// the Deep Tier — it deliberately loads without a proc-macro server, so
    /// macro-generated references are invisible (the documented trade-off on
    /// `judge::deep`'s `DeepContext::load`). [`FidelityStatus::NotApplicable`]
    /// at the Fast Tier.
    pub proc_macro_expansion: FidelityStatus,
    /// Whether build scripts ran (`OUT_DIR` code visible). Same tier logic
    /// as `proc_macro_expansion`: [`FidelityStatus::Disabled`] at the Deep
    /// Tier, [`FidelityStatus::NotApplicable`] at the Fast Tier.
    pub build_scripts: FidelityStatus,
    /// The judge version that produced this report (`CARGO_PKG_VERSION`).
    pub judge_version: String,
    /// Which tier produced this view: `"fast"` or `"deep"` (see
    /// `crate::AnalysisTier`).
    pub tier: String,
}

impl AnalysisUniverse {
    /// The Deep Tier view (`dead-code`, `explain --why-live`): a semantic
    /// workspace load under every Cargo feature, deliberately without a
    /// proc-macro server and without build scripts (see `judge::deep`).
    /// `include_generated` is fixed to `false`: generated files stay in the
    /// semantic graph but are never finding targets at the Deep Tier (see
    /// `crate::dead_code`).
    pub fn deep(workspace: &crate::ingest::Workspace, include_tests: bool) -> Self {
        let mut entry_points = vec!["fn-main-bin".to_string(), "fn-main-example".to_string()];
        if include_tests {
            entry_points.push("test".to_string());
            entry_points.push("bench".to_string());
        }
        entry_points.extend(
            ["no-mangle", "export-name", "wasm-bindgen"]
                .iter()
                .map(ToString::to_string),
        );
        Self {
            features: vec!["all".to_string()],
            entry_points,
            include_tests,
            proc_macro_expansion: FidelityStatus::Disabled,
            build_scripts: FidelityStatus::Disabled,
            tier: "deep".to_string(),
            ..Self::base(workspace)
        }
    }

    /// The Fast Tier view (`health`, bare `cargo judge`): a feature-blind
    /// syntactic pass over every discovered source file — no reachability
    /// (empty `entry_points`), tests always parsed, and nothing that could
    /// be expanded (both fidelity fields [`FidelityStatus::NotApplicable`]).
    pub fn fast(workspace: &crate::ingest::Workspace, include_generated: bool) -> Self {
        Self {
            include_generated,
            ..Self::base(workspace)
        }
    }

    /// The fields shared by both tiers, with Fast Tier defaults.
    fn base(workspace: &crate::ingest::Workspace) -> Self {
        let mut targets: Vec<String> = workspace
            .crates
            .iter()
            .flat_map(|krate| &krate.entry_points)
            .map(|entry| entry.kind.label().to_string())
            .collect();
        targets.sort();
        targets.dedup();
        Self {
            commit: crate::git::head_commit(&workspace.root).ok(),
            targets,
            features: Vec::new(),
            platform: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
            entry_points: Vec::new(),
            include_tests: true,
            include_generated: false,
            proc_macro_expansion: FidelityStatus::NotApplicable,
            build_scripts: FidelityStatus::NotApplicable,
            judge_version: env!("CARGO_PKG_VERSION").to_string(),
            tier: "fast".to_string(),
        }
    }
}

/// How many of a report's findings can affect a verdict vs. how many are
/// purely advisory (see [`EvidenceClass::is_gating`]). Additive report field
/// — per-finding classification is already carried by
/// `Finding.evidence_class`, this is just the pre-computed split so
/// consumers don't have to re-derive the gating policy.
#[derive(Debug, Clone, Serialize)]
pub struct VerdictEffectCounts {
    pub gating: usize,
    pub advisory: usize,
}

/// The versioned, agent-readable output envelope (see todo.md §7). Always
/// carries the full finding graph — TTY/Markdown reduce to root findings by
/// default, JSON never does. `findings` includes advisory (heuristic)
/// findings; `counts` records the gating/advisory split, and any verdict or
/// exit code derived from a report reflects only the gating findings
/// (todo.md §17.2, §17.5).
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema_version: u32,
    /// The analysis view this report's findings are claims about (see
    /// [`AnalysisUniverse`]). Additive in schema v2 — no version bump; the
    /// field is omitted from JSON when absent, so universe-less v2 reports
    /// stay valid. The Deep Tier always fills it (todo.md §0); Fast Tier
    /// commands may.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_universe: Option<AnalysisUniverse>,
    /// Gating vs. advisory finding counts (additive in schema v2 — no
    /// version bump; see [`VerdictEffectCounts`]).
    pub counts: VerdictEffectCounts,
    pub findings: Vec<Finding>,
    /// Analyzer failures that made the report incomplete. An empty list means
    /// every requested detector completed successfully.
    pub errors: Vec<String>,
    /// Findings dropped by an inline `// judge-ignore: <rule> — <reason>`
    /// comment before this report was built (see
    /// [`crate::suppression::apply_inline_suppressions`], todo.md §5) — the
    /// only trace a suppression leaves, since the findings themselves are
    /// gone as if they never fired. Additive in schema v2 — no version bump;
    /// omitted from JSON when zero, matching `analysis_universe`'s pattern.
    #[serde(skip_serializing_if = "is_zero")]
    pub suppressed_inline: usize,
    /// Per-crate public-API-surface item count (see
    /// [`crate::api_surface::ApiSurfaceSize`], todo.md §I "API-Surface-Größe
    /// pro Crate, Trend gegen Baseline") — additive, no version bump; only
    /// `cargo judge api-surface` fills it in, matching `analysis_universe`'s
    /// pattern of an omitted-when-absent field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_surface_size: Option<HashMap<String, usize>>,
}

fn is_zero(count: &usize) -> bool {
    *count == 0
}

impl Report {
    pub fn new(findings: Vec<Finding>) -> Self {
        Self::with_errors(findings, Vec::new())
    }

    pub fn with_errors(findings: Vec<Finding>, errors: Vec<String>) -> Self {
        let gating = findings.iter().filter(|f| f.is_gating()).count();
        Self {
            schema_version: SCHEMA_VERSION,
            analysis_universe: None,
            counts: VerdictEffectCounts {
                gating,
                advisory: findings.len() - gating,
            },
            findings,
            errors,
            suppressed_inline: 0,
            api_surface_size: None,
        }
    }

    /// Attaches the analysis view — builder-style, so the many existing
    /// [`Report::new`]/[`Report::with_errors`] call sites stay untouched and
    /// only the commands that describe their universe opt in.
    pub fn with_universe(mut self, universe: AnalysisUniverse) -> Self {
        self.analysis_universe = Some(universe);
        self
    }

    /// Records how many findings an inline `judge-ignore` comment dropped
    /// before this report was built — builder-style like [`with_universe`],
    /// so only commands that actually run the filter opt in.
    ///
    /// [`with_universe`]: Report::with_universe
    pub fn with_suppressed_inline(mut self, count: usize) -> Self {
        self.suppressed_inline = count;
        self
    }

    /// Attaches the per-crate api-surface-size count — builder-style like
    /// [`with_universe`](Self::with_universe), so only `cargo judge
    /// api-surface` opts in.
    pub fn with_api_surface_size(mut self, size: HashMap<String, usize>) -> Self {
        self.api_surface_size = Some(size);
        self
    }
}

/// Findings with no recorded cause — what TTY/Markdown show by default
/// (see todo.md §7 "Kausale Finding-Gruppen", §14.2 P0#2). `--show-cascades`
/// bypasses this and shows every finding, root or not.
pub fn root_findings(findings: &[Finding]) -> Vec<&Finding> {
    findings.iter().filter(|f| f.caused_by.is_empty()).collect()
}

/// Sorts findings worst-first (`Fail` before `Warn` before `Info`), stable
/// otherwise. Used to merge findings from multiple detectors into one
/// ranked view without inventing a numeric score across them (see todo.md
/// §4 "Decision Surface" — the score itself needs crate-type profiles that
/// don't exist yet; this is the part that doesn't).
pub fn sort_by_severity_desc(findings: &mut [Finding]) {
    findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));
}

/// Rewrites workspace-local absolute paths to repository-relative paths.
/// Finding ids embed their location in several detectors, so the id must be
/// rebased together with the structured location to remain stable across
/// different checkout directories. Causal edge references are rebased along
/// with the ids they point to, so exported `caused_by`/`causes` never dangle
/// after a rebase.
pub fn relativize_paths(findings: &mut [Finding], workspace_root: &Path) {
    let mut renames: HashMap<FindingId, FindingId> = HashMap::new();
    for finding in findings.iter_mut() {
        let Ok(relative) = finding.location.file.strip_prefix(workspace_root) else {
            continue;
        };
        let relative = relative.to_path_buf();
        // The id and item_path are UTF-8 strings, so the embedded path text
        // can only be rebased when both the absolute and the stripped path
        // render as valid UTF-8. A non-UTF-8 path can never appear verbatim
        // in an id; substituting its lossy rendering (as this function once
        // did) could corrupt an id that merely resembles it, so such paths
        // keep their id/item_path untouched and only the structured
        // location is rebased.
        if let (Some(absolute_text), Some(relative_text)) =
            (finding.location.file.to_str(), relative.to_str())
        {
            let rebased_id = finding.id.as_str().replace(absolute_text, relative_text);
            if rebased_id != finding.id.as_str() {
                let rebased_id = FindingId::from(rebased_id);
                renames.insert(finding.id.clone(), rebased_id.clone());
                finding.id = rebased_id;
            }
            if finding.location.item_path == absolute_text {
                finding.location.item_path = relative_text.to_string();
            }
        }
        finding.location.file = relative;
    }
    if renames.is_empty() {
        return;
    }
    for finding in findings {
        for edge_id in finding
            .caused_by
            .iter_mut()
            .chain(finding.causes.iter_mut())
        {
            if let Some(rebased) = renames.get(edge_id) {
                *edge_id = rebased.clone();
            }
        }
    }
}

/// Rejected [`FindingGraph`] mutations. Every invalid state is an error, not
/// a panic — callers decide how to surface it.
#[derive(Debug, PartialEq, Eq)]
pub enum GraphError {
    /// `add_finding` saw an id that is already in the graph.
    DuplicateFinding(FindingId),
    /// `add_edge` referenced an id with no finding in the graph.
    UnknownFinding(FindingId),
    /// `add_edge` saw a cause → effect pair that is already stored.
    DuplicateEdge { cause: FindingId, effect: FindingId },
    /// `add_edge` would close a loop; the path lists the finding ids that
    /// would form it (first and last entry are the same id).
    Cycle { cycle: Vec<FindingId> },
}

impl std::fmt::Display for GraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateFinding(id) => write!(f, "duplicate finding id: {id}"),
            Self::UnknownFinding(id) => write!(f, "edge references unknown finding id: {id}"),
            Self::DuplicateEdge { cause, effect } => {
                write!(f, "duplicate edge: {cause} -> {effect}")
            }
            Self::Cycle { cycle } => {
                let path: Vec<&str> = cycle.iter().map(FindingId::as_str).collect();
                write!(f, "cycle in finding graph: {}", path.join(" -> "))
            }
        }
    }
}

impl std::error::Error for GraphError {}

/// Sole owner of findings and their causal edges (todo.md §15.2). Each edge
/// is stored exactly once as a cause → effect pair; the per-finding
/// `caused_by`/`causes` views are derived from that one set, so root
/// reduction and cycle checking can never read diverging truths.
/// [`FindingGraph::into_findings`] exports findings with both directions
/// filled in, keeping the schema-v2 JSON shape unchanged.
#[derive(Debug, Default)]
pub struct FindingGraph {
    findings: Vec<Finding>,
    ids: Vec<FindingId>,
    index_by_id: HashMap<FindingId, usize>,
    /// `(cause, effect)` index pairs — the single stored edge direction.
    edges: BTreeSet<(usize, usize)>,
}

impl FindingGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a finding, rejecting ids already present in the graph. Callers
    /// pass findings without edges (detectors never set them; edges are
    /// attached via [`FindingGraph::add_edge`]).
    pub fn add_finding(&mut self, finding: Finding) -> Result<(), GraphError> {
        debug_assert!(
            finding.caused_by.is_empty() && finding.causes.is_empty(),
            "edges are owned by the graph; add them via add_edge"
        );
        let id = finding.id.clone();
        if self.index_by_id.contains_key(&id) {
            return Err(GraphError::DuplicateFinding(id));
        }
        self.index_by_id.insert(id.clone(), self.findings.len());
        self.ids.push(id);
        self.findings.push(finding);
        Ok(())
    }

    /// Records that `cause` caused `effect`. Rejects unknown ids, duplicate
    /// edges, and any edge that would close a cycle (including self-edges).
    pub fn add_edge(&mut self, cause: &FindingId, effect: &FindingId) -> Result<(), GraphError> {
        let cause_index = *self
            .index_by_id
            .get(cause)
            .ok_or_else(|| GraphError::UnknownFinding(cause.clone()))?;
        let effect_index = *self
            .index_by_id
            .get(effect)
            .ok_or_else(|| GraphError::UnknownFinding(effect.clone()))?;
        if self.edges.contains(&(cause_index, effect_index)) {
            return Err(GraphError::DuplicateEdge {
                cause: cause.clone(),
                effect: effect.clone(),
            });
        }
        if cause_index == effect_index {
            return Err(GraphError::Cycle {
                cycle: vec![cause.clone(), cause.clone()],
            });
        }
        let mut visited = vec![false; self.findings.len()];
        let mut path = Vec::new();
        if self.find_path(effect_index, cause_index, &mut visited, &mut path) {
            // `path` runs effect -> … -> cause; prepending the cause closes
            // the reported loop (first and last entry are the same id).
            let mut cycle = Vec::with_capacity(path.len() + 1);
            cycle.push(cause.clone());
            cycle.extend(path.iter().map(|&index| self.ids[index].clone()));
            return Err(GraphError::Cycle { cycle });
        }
        self.edges.insert((cause_index, effect_index));
        Ok(())
    }

    /// Depth-first search for a path `from` -> … -> `to` along stored edges,
    /// recording the node path when one exists.
    fn find_path(
        &self,
        from: usize,
        to: usize,
        visited: &mut [bool],
        path: &mut Vec<usize>,
    ) -> bool {
        path.push(from);
        if from == to {
            return true;
        }
        visited[from] = true;
        for &(_, next) in self.edges.range((from, usize::MIN)..=(from, usize::MAX)) {
            if !visited[next] && self.find_path(next, to, visited, path) {
                return true;
            }
        }
        path.pop();
        false
    }

    /// Findings with no recorded cause, in insertion order — the same edge
    /// set the cycle check validates.
    pub fn roots(&self) -> Vec<&Finding> {
        let mut has_cause = vec![false; self.findings.len()];
        for &(_, effect) in &self.edges {
            has_cause[effect] = true;
        }
        self.findings
            .iter()
            .zip(&has_cause)
            .filter(|(_, has_cause)| !**has_cause)
            .map(|(finding, _)| finding)
            .collect()
    }

    /// Findings that `id` caused (the cascade direction), derived from the
    /// stored edges. Unknown ids yield an empty list.
    pub fn causes_of(&self, id: &FindingId) -> Vec<&Finding> {
        let Some(&index) = self.index_by_id.get(id) else {
            return Vec::new();
        };
        self.edges
            .range((index, usize::MIN)..=(index, usize::MAX))
            .map(|&(_, effect)| &self.findings[effect])
            .collect()
    }

    /// Findings that caused `id` (the root-cause direction), derived from
    /// the stored edges. Unknown ids yield an empty list.
    pub fn caused_by_of(&self, id: &FindingId) -> Vec<&Finding> {
        let Some(&index) = self.index_by_id.get(id) else {
            return Vec::new();
        };
        self.edges
            .iter()
            .filter(|&&(_, effect)| effect == index)
            .map(|&(cause, _)| &self.findings[cause])
            .collect()
    }

    /// Consumes the graph and returns the findings in insertion order with
    /// `caused_by`/`causes` filled in from the single stored edge set — the
    /// serialized schema-v2 shape is exactly what it was when the fields
    /// were set directly.
    pub fn into_findings(mut self) -> Vec<Finding> {
        for &(cause, effect) in &self.edges {
            let cause_id = self.ids[cause].clone();
            let effect_id = self.ids[effect].clone();
            self.findings[cause].causes.push(effect_id);
            self.findings[effect].caused_by.push(cause_id);
        }
        self.findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &str) -> Finding {
        Finding::new(
            id.to_string(),
            "test-rule".to_string(),
            Severity::Warn,
            Location {
                file: PathBuf::from("src/lib.rs"),
                line: OneBasedLine::FIRST,
                item_path: "crate::lib".to_string(),
            },
            EvidenceClass::Heuristic,
            Origin::Code,
            None,
        )
    }

    fn id(value: &str) -> FindingId {
        FindingId::from(value)
    }

    fn graph_of(ids: &[&str]) -> FindingGraph {
        let mut graph = FindingGraph::new();
        for finding_id in ids {
            graph.add_finding(finding(finding_id)).unwrap();
        }
        graph
    }

    #[test]
    fn graph_rejects_duplicate_finding_ids() {
        let mut graph = graph_of(&["a"]);
        let err = graph.add_finding(finding("a")).unwrap_err();
        assert_eq!(err, GraphError::DuplicateFinding(id("a")));
        assert_eq!(graph.into_findings().len(), 1);
    }

    #[test]
    fn graph_rejects_edges_to_unknown_findings() {
        let mut graph = graph_of(&["a"]);
        let err = graph.add_edge(&id("a"), &id("dangling")).unwrap_err();
        assert_eq!(err, GraphError::UnknownFinding(id("dangling")));
        let err = graph.add_edge(&id("dangling"), &id("a")).unwrap_err();
        assert_eq!(err, GraphError::UnknownFinding(id("dangling")));
    }

    #[test]
    fn graph_rejects_duplicate_edges() {
        let mut graph = graph_of(&["a", "b"]);
        graph.add_edge(&id("a"), &id("b")).unwrap();
        let err = graph.add_edge(&id("a"), &id("b")).unwrap_err();
        assert_eq!(
            err,
            GraphError::DuplicateEdge {
                cause: id("a"),
                effect: id("b"),
            }
        );
    }

    #[test]
    fn graph_rejects_self_cycles() {
        let mut graph = graph_of(&["a"]);
        let err = graph.add_edge(&id("a"), &id("a")).unwrap_err();
        assert_eq!(
            err,
            GraphError::Cycle {
                cycle: vec![id("a"), id("a")],
            }
        );
    }

    #[test]
    fn graph_rejects_direct_cycles() {
        let mut graph = graph_of(&["a", "b"]);
        graph.add_edge(&id("a"), &id("b")).unwrap();
        let err = graph.add_edge(&id("b"), &id("a")).unwrap_err();
        assert_eq!(
            err,
            GraphError::Cycle {
                cycle: vec![id("b"), id("a"), id("b")],
            }
        );
    }

    #[test]
    fn graph_rejects_indirect_cycles_and_accepts_acyclic_edges() {
        let mut graph = graph_of(&["a", "b", "c"]);
        graph.add_edge(&id("a"), &id("b")).unwrap();
        graph.add_edge(&id("b"), &id("c")).unwrap();
        let err = graph.add_edge(&id("c"), &id("a")).unwrap_err();
        assert_eq!(
            err,
            GraphError::Cycle {
                cycle: vec![id("c"), id("a"), id("b"), id("c")],
            }
        );
    }

    #[test]
    fn graph_roots_are_findings_without_a_recorded_cause() {
        let mut graph = graph_of(&["a", "b", "c"]);
        graph.add_edge(&id("a"), &id("b")).unwrap();
        let root_ids: Vec<&str> = graph.roots().iter().map(|f| f.id.as_str()).collect();
        assert_eq!(root_ids, ["a", "c"]);
    }

    #[test]
    fn edge_directions_are_derived_from_the_single_stored_edge_set() {
        let mut graph = graph_of(&["a", "b", "c"]);
        graph.add_edge(&id("a"), &id("b")).unwrap();
        graph.add_edge(&id("a"), &id("c")).unwrap();

        let effects: Vec<&str> = graph
            .causes_of(&id("a"))
            .iter()
            .map(|f| f.id.as_str())
            .collect();
        assert_eq!(effects, ["b", "c"]);

        let causes: Vec<&str> = graph
            .caused_by_of(&id("b"))
            .iter()
            .map(|f| f.id.as_str())
            .collect();
        assert_eq!(causes, ["a"]);

        assert!(graph.causes_of(&id("missing")).is_empty());
        assert!(graph.caused_by_of(&id("missing")).is_empty());
    }

    #[test]
    fn graph_export_serializes_identically_to_the_v2_finding_shape() {
        let mut graph = graph_of(&["a", "b"]);
        graph.add_edge(&id("a"), &id("b")).unwrap();
        let findings = graph.into_findings();
        let json = serde_json::to_value(&findings).unwrap();

        assert_eq!(
            json,
            serde_json::json!([
                {
                    "id": "a",
                    "rule": "test-rule",
                    "severity": "warn",
                    "location": {
                        "file": "src/lib.rs",
                        "line": 1,
                        "item_path": "crate::lib",
                    },
                    "evidence_class": "heuristic",
                    "origin": "code",
                    "evidence": null,
                    "caused_by": [],
                    "causes": ["b"],
                },
                {
                    "id": "b",
                    "rule": "test-rule",
                    "severity": "warn",
                    "location": {
                        "file": "src/lib.rs",
                        "line": 1,
                        "item_path": "crate::lib",
                    },
                    "evidence_class": "heuristic",
                    "origin": "code",
                    "evidence": null,
                    "caused_by": ["a"],
                    "causes": [],
                },
            ])
        );
    }

    #[test]
    fn root_findings_excludes_those_with_a_recorded_cause() {
        let mut graph = graph_of(&["a", "b"]);
        graph.add_edge(&id("a"), &id("b")).unwrap();
        let findings = graph.into_findings();

        let roots = root_findings(&findings);

        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].id, "a");
    }

    #[test]
    fn report_serializes_with_schema_version_and_snake_case_enums() {
        let report = Report::new(vec![finding("a")]);
        let json = serde_json::to_value(&report).unwrap();

        assert_eq!(json["schema_version"], SCHEMA_VERSION);
        assert_eq!(json["findings"][0]["severity"], "warn");
        assert_eq!(json["findings"][0]["origin"], "code");
        assert_eq!(json["findings"][0]["evidence_class"], "heuristic");
        assert_eq!(json["counts"]["gating"], 0);
        assert_eq!(json["counts"]["advisory"], 1);
        assert_eq!(json["errors"], serde_json::json!([]));
    }

    #[test]
    fn only_heuristic_findings_are_advisory() {
        let mut gating = finding("gating");
        gating.evidence_class = EvidenceClass::DerivedFact;
        assert!(gating.is_gating());
        gating.evidence_class = EvidenceClass::BoundedSemantic;
        assert!(gating.is_gating());
        gating.evidence_class = EvidenceClass::ExternalMeasurement;
        assert!(gating.is_gating());

        let advisory = finding("advisory");
        assert_eq!(advisory.evidence_class, EvidenceClass::Heuristic);
        assert!(!advisory.is_gating());
    }

    #[test]
    fn sort_by_severity_desc_puts_fail_before_warn_before_info() {
        let mut info = finding("info");
        info.severity = Severity::Info;
        let mut warn = finding("warn");
        warn.severity = Severity::Warn;
        let mut fail = finding("fail");
        fail.severity = Severity::Fail;

        let mut findings = vec![info, warn, fail];
        sort_by_severity_desc(&mut findings);

        let ids: Vec<_> = findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["fail", "warn", "info"]);
    }

    #[test]
    fn one_based_line_serializes_as_the_bare_number_and_rejects_zero() {
        assert!(OneBasedLine::new(0).is_none());
        let line = OneBasedLine::new(42).unwrap();
        assert_eq!(line.get(), 42);
        assert_eq!(serde_json::to_value(line).unwrap(), serde_json::json!(42));
        assert_eq!(
            serde_json::from_value::<OneBasedLine>(serde_json::json!(42)).unwrap(),
            line
        );
        assert!(serde_json::from_value::<OneBasedLine>(serde_json::json!(0)).is_err());
    }

    #[test]
    fn relativize_paths_rebases_location_and_embedded_id() {
        let mut finding = finding("hotspot:/tmp/project/src/lib.rs");
        finding.location.file = PathBuf::from("/tmp/project/src/lib.rs");
        finding.location.item_path = "/tmp/project/src/lib.rs".to_string();

        relativize_paths(
            std::slice::from_mut(&mut finding),
            Path::new("/tmp/project"),
        );

        assert_eq!(finding.id, "hotspot:src/lib.rs");
        assert_eq!(finding.location.file, PathBuf::from("src/lib.rs"));
        assert_eq!(finding.location.item_path, "src/lib.rs");
    }

    #[test]
    fn relativize_paths_rebases_edge_references_alongside_ids() {
        let mut graph = FindingGraph::new();
        let mut cause = finding("hotspot:/tmp/project/src/lib.rs");
        cause.location.file = PathBuf::from("/tmp/project/src/lib.rs");
        graph.add_finding(cause).unwrap();
        graph.add_finding(finding("other")).unwrap();
        graph
            .add_edge(&id("hotspot:/tmp/project/src/lib.rs"), &id("other"))
            .unwrap();
        let mut findings = graph.into_findings();

        relativize_paths(&mut findings, Path::new("/tmp/project"));

        assert_eq!(findings[0].id, "hotspot:src/lib.rs");
        assert_eq!(findings[0].causes, vec![id("other")]);
        assert_eq!(findings[1].caused_by, vec![id("hotspot:src/lib.rs")]);
    }

    /// A minimal real workspace with a lib and a bin target, loaded through
    /// the ingest layer — [`AnalysisUniverse`] describes an ingested
    /// workspace, so its tests need one. Not a git repository, so `commit`
    /// is honestly `None`.
    fn fixture_workspace(dir: &crate::test_util::TempDir) -> crate::ingest::Workspace {
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "universe-fixture"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn hello() {}\n").unwrap();
        std::fs::write(dir.join("src/main.rs"), "fn main() {}\n").unwrap();
        crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap()
    }

    #[test]
    fn deep_universe_is_fully_populated_and_reflects_include_tests() {
        let dir = crate::test_util::TempDir::new("universe-deep");
        let workspace = fixture_workspace(&dir);

        let with_tests = AnalysisUniverse::deep(&workspace, true);
        assert_eq!(with_tests.tier, "deep");
        assert_eq!(with_tests.commit, None, "fixture is not a git repository");
        assert_eq!(with_tests.targets, ["bin", "lib"]);
        assert_eq!(with_tests.features, ["all"]);
        assert!(!with_tests.platform.is_empty());
        assert!(with_tests.include_tests);
        assert!(!with_tests.include_generated);
        assert_eq!(
            with_tests.entry_points,
            [
                "fn-main-bin",
                "fn-main-example",
                "test",
                "bench",
                "no-mangle",
                "export-name",
                "wasm-bindgen"
            ]
        );
        assert_eq!(with_tests.proc_macro_expansion, FidelityStatus::Disabled);
        assert_eq!(with_tests.build_scripts, FidelityStatus::Disabled);
        assert_eq!(with_tests.judge_version, env!("CARGO_PKG_VERSION"));

        let without_tests = AnalysisUniverse::deep(&workspace, false);
        assert!(!without_tests.include_tests);
        assert!(
            !without_tests.entry_points.iter().any(|kind| kind == "test")
                && !without_tests
                    .entry_points
                    .iter()
                    .any(|kind| kind == "bench"),
            "test/bench entry-point kinds must only be listed with --include-tests"
        );
    }

    #[test]
    fn fast_universe_reports_not_applicable_fidelity_and_no_entry_point_model() {
        let dir = crate::test_util::TempDir::new("universe-fast");
        let workspace = fixture_workspace(&dir);

        let universe = AnalysisUniverse::fast(&workspace, true);
        assert_eq!(universe.tier, "fast");
        assert_eq!(universe.targets, ["bin", "lib"]);
        assert!(
            universe.features.is_empty(),
            "the Fast Tier is feature-blind and must not claim a feature selection"
        );
        assert!(
            universe.entry_points.is_empty(),
            "the Fast Tier makes no reachability claims and has no entry-point model"
        );
        assert!(universe.include_tests);
        assert!(universe.include_generated);
        assert_eq!(universe.proc_macro_expansion, FidelityStatus::NotApplicable);
        assert_eq!(universe.build_scripts, FidelityStatus::NotApplicable);
        assert_eq!(universe.judge_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn report_serializes_universe_when_present_and_omits_it_when_absent() {
        let bare = Report::new(Vec::new());
        let bare_json = serde_json::to_value(&bare).unwrap();
        assert!(
            bare_json.get("analysis_universe").is_none(),
            "a universe-less v2 report must omit the field, not emit null"
        );
        assert_eq!(bare_json["schema_version"], SCHEMA_VERSION);

        let dir = crate::test_util::TempDir::new("universe-serialize");
        let workspace = fixture_workspace(&dir);
        let report =
            Report::new(Vec::new()).with_universe(AnalysisUniverse::deep(&workspace, true));
        let json = serde_json::to_value(&report).unwrap();

        let universe = &json["analysis_universe"];
        assert_eq!(universe["tier"], "deep");
        assert_eq!(universe["commit"], serde_json::Value::Null);
        assert_eq!(universe["targets"], serde_json::json!(["bin", "lib"]));
        assert_eq!(universe["features"], serde_json::json!(["all"]));
        assert_eq!(universe["include_tests"], true);
        assert_eq!(universe["include_generated"], false);
        assert_eq!(universe["proc_macro_expansion"], "disabled");
        assert_eq!(universe["build_scripts"], "disabled");
        assert_eq!(universe["judge_version"], env!("CARGO_PKG_VERSION"));
        assert!(
            universe["entry_points"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("fn-main-bin"))
        );
    }
}
