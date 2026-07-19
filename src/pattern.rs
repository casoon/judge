//! Pattern-candidate recommendations aggregated from projectwide evidence
//! (see todo.md §16 "Rust-Pattern-Empfehlungen aus projektweiter Evidenz").
//!
//! This is deliberately **not** the `Finding`/`Report`/verdict path: a
//! [`PatternCandidate`] is a heuristic design suggestion, never a gating
//! result. Nothing in this module is wired into `evidence_class_for_rule`,
//! the health score, or a baseline verdict (todo.md §16.1 "Pattern-
//! Empfehlungen sind keine normalen Findings").
//!
//! Scope of this module (MVP slice, todo.md §16.6):
//! [`PatternCandidate`]/[`CorroboratedEvidence`] plus the five §16.3 MVP
//! aggregation rules — `stringly-error-boundary`, `primitive-domain-value`,
//! `boolean-state-cluster`, `public-invariant-bypass`, and
//! `manual-resource-lifecycle` (see [`analyze_workspace`]). The latter four
//! are listed as "Deep" tier in todo.md §16.3's rule table; the versions
//! implemented here are deliberately narrower, Fast-Tier-reachable subsets
//! of their full definitions (see each rule function's doc comment for the
//! exact narrowing). The broader `PrincipleHeuristic` type from todo.md
//! §16.7 (abstract design-principle heuristics like SRP/KISS/YAGNI) is a
//! deliberately separate, later slice and is not implemented here.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Serialize;
use syn::visit::Visit;

use crate::finding::{Finding, FindingId};
use crate::ingest::{CrateInfo, Workspace};

/// The rule id for the `stringly-error-boundary` aggregation implemented in
/// this module (see todo.md §16.3's rule table). Distinct from a
/// [`RustPattern`] — the rule is the *evidence pattern* judge looks for, the
/// pattern is the *recommendation* it emits.
pub const STRINGLY_ERROR_BOUNDARY_RULE: &str = "stringly-error-boundary";

/// The rule id for the `primitive-domain-value` aggregation implemented in
/// this module (see [`primitive_domain_value_candidates`]).
pub const PRIMITIVE_DOMAIN_VALUE_RULE: &str = "primitive-domain-value";

/// The rule id for the `boolean-state-cluster` aggregation implemented in
/// this module (see [`boolean_state_cluster_candidates`]).
pub const BOOLEAN_STATE_CLUSTER_RULE: &str = "boolean-state-cluster";

/// The rule id for the `public-invariant-bypass` aggregation implemented in
/// this module (see [`public_invariant_bypass_candidates`]).
pub const PUBLIC_INVARIANT_BYPASS_RULE: &str = "public-invariant-bypass";

/// The rule id for the `manual-resource-lifecycle` aggregation implemented in
/// this module (see [`manual_resource_lifecycle_candidates`]).
pub const MANUAL_RESOURCE_LIFECYCLE_RULE: &str = "manual-resource-lifecycle";

/// A recommended Rust design pattern (todo.md §16.2, §16.3). Exactly the enum
/// from the todo.md sketch — no additional variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RustPattern {
    ValidatedNewtype,
    SmartConstructor,
    StateEnum,
    TypeState,
    Builder,
    OptionsStruct,
    RaiiGuard,
    DomainError,
    FunctionalCore,
    EncapsulatedAggregate,
}

impl RustPattern {
    /// Stable kebab-case identifier, used both for [`PatternCandidateId`]
    /// computation and TTY rendering.
    pub const fn slug(self) -> &'static str {
        match self {
            Self::ValidatedNewtype => "validated-newtype",
            Self::SmartConstructor => "smart-constructor",
            Self::StateEnum => "state-enum",
            Self::TypeState => "type-state",
            Self::Builder => "builder",
            Self::OptionsStruct => "options-struct",
            Self::RaiiGuard => "raii-guard",
            Self::DomainError => "domain-error",
            Self::FunctionalCore => "functional-core",
            Self::EncapsulatedAggregate => "encapsulated-aggregate",
        }
    }
}

impl std::fmt::Display for RustPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.slug())
    }
}

/// Where a [`PatternCandidate`] applies: a crate, and (if the evidence
/// concentrates on specific items) the qualified item paths within it.
/// Deliberately not [`crate::finding::Location`] — that type is a single
/// file/line/item anchor for a line-precise finding, while a pattern
/// candidate is crate- or module-wide by construction (todo.md §16.1: many
/// local symptoms are aggregated into one design decision, so there is no
/// single line to anchor to).
#[derive(Debug, Clone, Serialize)]
pub struct CodeScope {
    /// The crate this candidate concerns (see [`CrateInfo::name`]).
    pub krate: String,
    /// Qualified item paths the evidence concentrates on, deduplicated and
    /// sorted. Empty when the candidate concerns the crate as a whole rather
    /// than specific items.
    pub modules: Vec<String>,
}

/// A single evidenced location backing an [`Evidence`] entry — a file, and
/// (if the evidence is item-scoped rather than file-scoped) a qualified item
/// path within it.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceLocation {
    pub file: PathBuf,
    pub item_path: Option<String>,
}

/// One piece of evidence: a human-readable description of what was observed
/// (phrased as an observation, never as an absolute claim — see todo.md
/// §16.7 "Sprachdisziplin"), plus the concrete locations backing it so the
/// claim stays checkable rather than asserted.
#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub description: String,
    pub locations: Vec<EvidenceLocation>,
}

/// At least two independently sourced signals corroborating one
/// [`PatternCandidate`] (todo.md §16.2, §16.6: "mindestens zwei unabhängige
/// Evidenzpunkte; andernfalls wird sie standardmäßig unterdrückt"). `primary`
/// and `independent` are mandatory and must come from different detection
/// mechanisms; `additional` holds any further corroborating signal beyond
/// those two.
#[derive(Debug, Clone, Serialize)]
pub struct CorroboratedEvidence {
    pub primary: Evidence,
    pub independent: Evidence,
    pub additional: Vec<Evidence>,
}

/// A situation in which the current structure can already be justified —
/// mandatory on every [`PatternCandidate`] (todo.md §16.4 "Gegenindikationen
/// sind Pflicht").
#[derive(Debug, Clone, Serialize)]
pub struct Contraindication {
    pub description: String,
}

/// A condition the recommendation assumes holds (e.g. "several boundary
/// functions in this crate convert errors the same way").
#[derive(Debug, Clone, Serialize)]
pub struct Precondition {
    pub description: String,
}

/// One numbered step of a migration plan. Text only — no patch is generated
/// (todo.md §16.5: "liefert zunächst nur einen geordneten Migrationsplan und
/// betroffene API-/Call-Sites, noch keinen Patch"). `affected_paths` names
/// the call sites/files that step concerns, when known.
#[derive(Debug, Clone, Serialize)]
pub struct MigrationStep {
    pub step: u32,
    pub description: String,
    pub affected_paths: Vec<PathBuf>,
}

/// Stable identifier for a [`PatternCandidate`], analogous in spirit to how
/// [`FindingId`] identifies a `Finding` — but composed differently, since a
/// pattern candidate has no single file/line to anchor an id string to.
/// Deterministically hashed from `(pattern, normalized scope, sorted
/// evidence identities)` (todo.md §16.5: "stabile ID aus Pattern,
/// normalisiertem Scope und Evidenzidentitäten bilden").
///
/// Note on the hash function: the task brief for this module referenced
/// Finding ids as a `b3:`-style blake3 hash and assumed blake3 was already a
/// project dependency. Neither holds for this codebase: `Finding` ids are
/// plain descriptive `rule:file:line:column` strings (see
/// `SlopVisitor::record` in `slop.rs`), and blake3 is not in `Cargo.toml`.
/// Adding a new dependency for a single hash call isn't justified, so this
/// uses a small hand-rolled, version-independent FNV-1a hash instead of
/// either blake3 or `std::hash::DefaultHasher` (whose algorithm is
/// explicitly not guaranteed stable across Rust releases — unsuitable for an
/// id meant to stay stable across judge upgrades).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PatternCandidateId(String);

impl PatternCandidateId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn compute(pattern: RustPattern, scope: &CodeScope, evidence_identities: &[String]) -> Self {
        let mut modules = scope.modules.clone();
        modules.sort();
        let mut identities = evidence_identities.to_vec();
        identities.sort();
        identities.dedup();
        let normalized = format!(
            "{}|{}|{}|{}",
            pattern.slug(),
            scope.krate,
            modules.join(","),
            identities.join(",")
        );
        Self(format!(
            "pattern:{}:{}",
            pattern.slug(),
            fnv1a_hex(&normalized)
        ))
    }
}

impl std::fmt::Display for PatternCandidateId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Deterministic, version-independent 64-bit FNV-1a hash, hex-encoded. See
/// [`PatternCandidateId`]'s doc comment for why this exists instead of
/// blake3 or `std::hash::DefaultHasher`.
fn fnv1a_hex(input: &str) -> String {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for byte in input.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:016x}")
}

/// A pattern recommendation aggregated from corroborated projectwide
/// evidence (todo.md §16.2). Exactly the struct from the todo.md sketch, plus
/// one deliberate omission: there is no `confidence` field. That is a type-
/// level guarantee, not a convention — nothing in this module (or anywhere
/// else) can attach `PatternCandidate` to `Finding`/`Report`/the verdict
/// path, so this aggregate can never be serialized as a gating result
/// (todo.md §16.7: "Der Typ selbst garantiert, dass diese Aussage nie als...
/// CI-Verletzung serialisiert werden kann").
#[derive(Debug, Clone, Serialize)]
pub struct PatternCandidate {
    pub id: PatternCandidateId,
    pub pattern: RustPattern,
    pub scope: CodeScope,
    pub evidence: CorroboratedEvidence,
    pub preconditions: Vec<Precondition>,
    pub contraindications: Vec<Contraindication>,
    pub migration: Vec<MigrationStep>,
    pub related_findings: Vec<FindingId>,
}

/// Runs every implemented pattern-aggregation rule over `workspace` and
/// `findings` (the combined output of `judge::slop::analyze_workspace`, or
/// any superset of it): `stringly-error-boundary`, `primitive-domain-value`,
/// `boolean-state-cluster`, `public-invariant-bypass`, and
/// `manual-resource-lifecycle` — this is the dispatch point future rules
/// from todo.md §16.3 attach to.
pub fn analyze_workspace(workspace: &Workspace, findings: &[Finding]) -> Vec<PatternCandidate> {
    let mut candidates = stringly_error_boundary_candidates(workspace, findings);
    candidates.extend(primitive_domain_value_candidates(workspace));
    candidates.extend(boolean_state_cluster_candidates(workspace));
    candidates.extend(public_invariant_bypass_candidates(workspace));
    candidates.extend(manual_resource_lifecycle_candidates(workspace));
    candidates
}

/// `stringly-error-boundary` (todo.md §16.3): concrete errors are converted
/// to `String`/context-free collectors at module/crate boundaries, while the
/// crate already has the raw material for a proper domain error. Requires
/// two independent signals per crate (todo.md §16.6's "mindestens zwei
/// unabhängige Evidenzpunkte", refined further by this rule's own brief:
/// signal 1 alone additionally needs at least two occurrences to count as a
/// pattern rather than a one-off):
///
/// 1. **Primary** — at least two `catch-all-error` findings within the same
///    crate (a syntax fact judge already computes; see `crate::slop`).
/// 2. **Independent** — the same crate already defines at least one typed
///    error (an enum with `Error` in its name, an item carrying an
///    `Error`-suffixed derive such as `#[derive(thiserror::Error)]`, or an
///    `impl ... Error for ...`) — a structural-availability fact, not a
///    syntax-frequency one.
///
/// Only crates satisfying both produce a candidate — exactly one per crate,
/// referencing every contributing `catch-all-error` finding.
fn stringly_error_boundary_candidates(
    workspace: &Workspace,
    findings: &[Finding],
) -> Vec<PatternCandidate> {
    let mut by_crate: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for finding in findings {
        if finding.rule.as_str() != crate::slop::CATCH_ALL_ERROR_RULE {
            continue;
        }
        let Some(krate) = crate_for_file(workspace, &finding.location.file) else {
            continue;
        };
        by_crate
            .entry(krate.name.as_str())
            .or_default()
            .push(finding);
    }

    let mut candidates = Vec::new();
    for (krate_name, crate_findings) in by_crate {
        if crate_findings.len() < 2 {
            continue;
        }
        let Some(krate) = workspace.crates.iter().find(|k| k.name == krate_name) else {
            continue;
        };
        let Some(independent) = crate_defines_typed_error(krate) else {
            continue;
        };
        candidates.push(build_candidate(krate, &crate_findings, independent));
    }
    candidates
}

/// The crate a source file belongs to, matched against each crate's known
/// source-file list (populated by `judge::ingest::load`).
fn crate_for_file<'a>(workspace: &'a Workspace, file: &Path) -> Option<&'a CrateInfo> {
    workspace
        .crates
        .iter()
        .find(|krate| krate.source_files.iter().any(|source| source.path == file))
}

fn build_candidate(
    krate: &CrateInfo,
    crate_findings: &[&Finding],
    independent: Evidence,
) -> PatternCandidate {
    let mut related_findings: Vec<FindingId> = crate_findings
        .iter()
        .map(|finding| finding.id.clone())
        .collect();
    related_findings.sort_by(|a, b| a.as_str().cmp(b.as_str()));

    let mut modules: Vec<String> = crate_findings
        .iter()
        .map(|finding| finding.location.item_path.clone())
        .collect();
    modules.sort();
    modules.dedup();

    let scope = CodeScope {
        krate: krate.name.clone(),
        modules,
    };

    let mut primary_locations: Vec<EvidenceLocation> = crate_findings
        .iter()
        .map(|finding| EvidenceLocation {
            file: finding.location.file.clone(),
            item_path: Some(finding.location.item_path.clone()),
        })
        .collect();
    primary_locations.sort_by(|a, b| (&a.file, &a.item_path).cmp(&(&b.file, &b.item_path)));

    let mut affected_paths: Vec<PathBuf> = crate_findings
        .iter()
        .map(|finding| finding.location.file.clone())
        .collect();
    affected_paths.sort();
    affected_paths.dedup();

    let primary = Evidence {
        description: format!(
            "{} `catch-all-error` finding(s) in crate `{}` convert concrete errors to \
             `String`/`Box<dyn Error>`/context-free collectors at public boundaries.",
            crate_findings.len(),
            krate.name
        ),
        locations: primary_locations,
    };

    let evidence_identities: Vec<String> = related_findings
        .iter()
        .map(|id| id.as_str().to_string())
        .collect();

    let id = PatternCandidateId::compute(RustPattern::DomainError, &scope, &evidence_identities);

    PatternCandidate {
        id,
        pattern: RustPattern::DomainError,
        scope,
        evidence: CorroboratedEvidence {
            primary,
            independent,
            additional: Vec::new(),
        },
        preconditions: vec![Precondition {
            description: format!(
                "Mehrere Boundary-Funktionen in Crate `{}` wandeln unterschiedliche \
                 Fehlerquellen an derselben Grenze in `anyhow`/`Box<dyn Error>`/`String` um.",
                krate.name
            ),
        }],
        contraindications: vec![
            Contraindication {
                description: "Die Grenze kann bewusst ein Kompatibilitäts-Shim sein, der \
                    verschiedene Fehlerquellen absichtlich vereinheitlicht."
                    .to_string(),
            },
            Contraindication {
                description: "Ein zusätzliches Domain-Error-Enum kann bei sehr wenigen \
                    Aufrufstellen mehr Boilerplate als Nutzen erzeugen."
                    .to_string(),
            },
        ],
        migration: vec![
            MigrationStep {
                step: 1,
                description: "Gemeinsame Fehlerquellen an dieser Grenze identifizieren."
                    .to_string(),
                affected_paths: affected_paths.clone(),
            },
            MigrationStep {
                step: 2,
                description: "Domain-Error-Enum mit einer Variante pro Quelle entwerfen."
                    .to_string(),
                affected_paths: Vec::new(),
            },
            MigrationStep {
                step: 3,
                description: "`From`-Impls für die Quellfehler ergänzen.".to_string(),
                affected_paths: Vec::new(),
            },
            MigrationStep {
                step: 4,
                description: "Boundary-Funktionen auf das neue Enum umstellen und `?` statt \
                    manueller Konvertierung nutzen."
                    .to_string(),
                affected_paths,
            },
        ],
        related_findings,
    }
}

/// Whether `krate` already defines at least one typed error (see
/// [`stringly_error_boundary_candidates`]'s signal 2). Reads and parses every
/// source file in the crate with `syn`; a file that fails to read or parse
/// is silently skipped rather than surfaced as an analyzer error — this is a
/// best-effort corroborating signal, not the primary evidence, and skipping
/// an unreadable file just means one less place this signal could have come
/// from.
fn crate_defines_typed_error(krate: &CrateInfo) -> Option<Evidence> {
    let mut hits = Vec::new();
    for source in &krate.source_files {
        let Ok(text) = std::fs::read_to_string(&source.path) else {
            continue;
        };
        let Ok(ast) = syn::parse_file(&text) else {
            continue;
        };
        let mut visitor = TypedErrorVisitor {
            file: &source.path,
            path: Vec::new(),
            hits: Vec::new(),
        };
        visitor.visit_file(&ast);
        hits.append(&mut visitor.hits);
    }
    if hits.is_empty() {
        return None;
    }
    hits.sort_by(|a, b| (&a.file, &a.item_path).cmp(&(&b.file, &b.item_path)));
    Some(Evidence {
        description: format!(
            "Crate `{}` already defines {} typed error item(s) in its own source (an enum with \
             `Error` in its name, an `Error`-deriving item, or an `impl ... Error for ...`) — \
             the raw material for a domain error already exists in this crate.",
            krate.name,
            hits.len()
        ),
        locations: hits,
    })
}

/// Collects candidate typed-error item locations: `enum`s named `*Error*`,
/// any item carrying a derive ending in `Error` (covers
/// `#[derive(thiserror::Error)]` without depending on the `thiserror` crate
/// itself), and `impl ... Error for ...` blocks.
struct TypedErrorVisitor<'a> {
    file: &'a Path,
    path: Vec<String>,
    hits: Vec<EvidenceLocation>,
}

impl TypedErrorVisitor<'_> {
    fn current_item_path(&self) -> String {
        if self.path.is_empty() {
            self.file.display().to_string()
        } else {
            self.path.join("::")
        }
    }

    fn record(&mut self) {
        self.hits.push(EvidenceLocation {
            file: self.file.to_path_buf(),
            item_path: Some(self.current_item_path()),
        });
    }
}

impl<'ast> Visit<'ast> for TypedErrorVisitor<'_> {
    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        self.path.push(node.ident.to_string());
        if node.ident.to_string().contains("Error") || has_derive_ending_in(&node.attrs, "Error") {
            self.record();
        }
        syn::visit::visit_item_enum(self, node);
        self.path.pop();
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        self.path.push(node.ident.to_string());
        if has_derive_ending_in(&node.attrs, "Error") {
            self.record();
        }
        syn::visit::visit_item_struct(self, node);
        self.path.pop();
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        use quote::ToTokens;
        self.path.push(node.self_ty.to_token_stream().to_string());
        if let Some((_, path, _)) = &node.trait_
            && path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "Error")
        {
            self.record();
        }
        syn::visit::visit_item_impl(self, node);
        self.path.pop();
    }
}

/// Whether any `#[derive(...)]` attribute in `attrs` lists a path ending in
/// `ident` (e.g. `#[derive(thiserror::Error)]` for `ident == "Error"`).
fn has_derive_ending_in(attrs: &[syn::Attribute], ident: &str) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("derive") {
            return false;
        }
        let syn::Meta::List(list) = &attr.meta else {
            return false;
        };
        list.parse_args_with(
            syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
        )
        .is_ok_and(|paths| {
            paths.iter().any(|path| {
                path.segments
                    .last()
                    .is_some_and(|segment| segment.ident == ident)
            })
        })
    })
}

/// `primitive-domain-value` (todo.md §16.3): the same primitive value is
/// validated identically at several boundaries, or only ever used within a
/// restricted range.
///
/// **This is a deliberately narrower, Fast-Tier-reachable subset of the full
/// rule from todo.md §16.3** (which is listed there as "Deep" tier). The
/// full rule can reason about validation performed anywhere a value flows,
/// across crates, and via non-syntactic evidence (e.g. Deep-Tier semantic
/// analysis of call sites). This implementation only looks at:
///
/// 1. **Primary** — the same (parameter name, type) pair appears as a
///    parameter in at least two *different* `pub fn` signatures within the
///    *same crate*. Types are restricted to `u8`/`u16`/`u32`/`u64`/`usize`/
///    `i8`/`i16`/`i32`/`i64`/`isize`/`f32`/`f64`/`String`/`&str` (`bool` is
///    deliberately excluded — that is [`boolean_state_cluster_candidates`]'s
///    domain, not this rule's).
/// 2. **Independent** — at least one of those signatures has a validation
///    guard referencing the parameter within the function body: an `if`
///    whose condition references the parameter and whose then-branch
///    returns `Err(...)` or calls `panic!(...)`, or an `assert!(...)` whose
///    arguments reference the parameter.
///
/// Only (crate, parameter name, type) tuples satisfying both produce a
/// candidate — exactly one per tuple, referencing every contributing
/// signature.
fn primitive_domain_value_candidates(workspace: &Workspace) -> Vec<PatternCandidate> {
    let mut candidates = Vec::new();
    for krate in &workspace.crates {
        let mut facts: Vec<SignatureParamFact> = Vec::new();
        for source in &krate.source_files {
            let Ok(text) = std::fs::read_to_string(&source.path) else {
                continue;
            };
            let Ok(ast) = syn::parse_file(&text) else {
                continue;
            };
            let mut visitor = PrimitiveDomainValueVisitor {
                file: &source.path,
                self_type: None,
                facts: Vec::new(),
            };
            visitor.visit_file(&ast);
            facts.append(&mut visitor.facts);
        }

        let mut by_param: BTreeMap<(String, String), Vec<SignatureParamFact>> = BTreeMap::new();
        for fact in facts {
            by_param
                .entry((fact.param.clone(), fact.type_name.clone()))
                .or_default()
                .push(fact);
        }

        for ((param, type_name), group) in by_param {
            if group.len() < 2 {
                continue;
            }
            if !group.iter().any(|fact| fact.has_guard) {
                continue;
            }
            candidates.push(build_primitive_domain_value_candidate(
                krate, &param, &type_name, &group,
            ));
        }
    }
    candidates
}

/// One `pub fn` parameter matching [`primitive_domain_value_candidates`]'s
/// type restriction, plus whether the function body guards it.
struct SignatureParamFact {
    file: PathBuf,
    item_path: String,
    param: String,
    type_name: String,
    has_guard: bool,
}

fn build_primitive_domain_value_candidate(
    krate: &CrateInfo,
    param: &str,
    type_name: &str,
    group: &[SignatureParamFact],
) -> PatternCandidate {
    let mut modules: Vec<String> = group.iter().map(|fact| fact.item_path.clone()).collect();
    modules.sort();
    modules.dedup();
    let scope = CodeScope {
        krate: krate.name.clone(),
        modules,
    };

    let mut primary_locations: Vec<EvidenceLocation> = group
        .iter()
        .map(|fact| EvidenceLocation {
            file: fact.file.clone(),
            item_path: Some(fact.item_path.clone()),
        })
        .collect();
    primary_locations.sort_by(|a, b| (&a.file, &a.item_path).cmp(&(&b.file, &b.item_path)));

    let mut guard_locations: Vec<EvidenceLocation> = group
        .iter()
        .filter(|fact| fact.has_guard)
        .map(|fact| EvidenceLocation {
            file: fact.file.clone(),
            item_path: Some(fact.item_path.clone()),
        })
        .collect();
    guard_locations.sort_by(|a, b| (&a.file, &a.item_path).cmp(&(&b.file, &b.item_path)));

    let primary = Evidence {
        description: format!(
            "Parameter `{param}: {type_name}` appears with the same name and type in {} `pub \
             fn` signature(s) in crate `{}`.",
            group.len(),
            krate.name
        ),
        locations: primary_locations,
    };
    let independent = Evidence {
        description: format!(
            "At least one of these signatures guards `{param}` with an early error/panic path \
             referencing the parameter (`if` + `return Err(...)`, `if` + `panic!(...)`, or \
             `assert!(...)`)."
        ),
        locations: guard_locations,
    };

    let evidence_identities: Vec<String> = primary
        .locations
        .iter()
        .map(|location| {
            format!(
                "{}:{}",
                location.file.display(),
                location.item_path.as_deref().unwrap_or("")
            )
        })
        .collect();
    let id =
        PatternCandidateId::compute(RustPattern::ValidatedNewtype, &scope, &evidence_identities);

    let mut affected_paths: Vec<PathBuf> = group.iter().map(|fact| fact.file.clone()).collect();
    affected_paths.sort();
    affected_paths.dedup();

    PatternCandidate {
        id,
        pattern: RustPattern::ValidatedNewtype,
        scope,
        evidence: CorroboratedEvidence {
            primary,
            independent,
            additional: Vec::new(),
        },
        preconditions: vec![Precondition {
            description: format!(
                "Crate `{}` verwendet `{param}: {type_name}` wiederholt als Parametername/-typ, \
                 und mindestens eine Fundstelle validiert den Wertebereich explizit.",
                krate.name
            ),
        }],
        contraindications: vec![
            Contraindication {
                description: "Der Parametername kann in verschiedenen Funktionen tatsächlich \
                    unterschiedliche Bedeutungen haben, auch wenn Name und Typ übereinstimmen."
                    .to_string(),
            },
            Contraindication {
                description: "Bei nur einer Validierungsstelle könnte ein Newtype mehr \
                    Boilerplate als Nutzen erzeugen, falls die übrigen Aufrufstellen den Wert nie \
                    direkt validieren müssen."
                    .to_string(),
            },
        ],
        migration: vec![
            MigrationStep {
                step: 1,
                description: "Newtype für den Wertebereich definieren.".to_string(),
                affected_paths: Vec::new(),
            },
            MigrationStep {
                step: 2,
                description: "`TryFrom<...>` mit der gefundenen Validierungslogik implementieren."
                    .to_string(),
                affected_paths: Vec::new(),
            },
            MigrationStep {
                step: 3,
                description: "Betroffene Signaturen schrittweise auf den Newtype umstellen."
                    .to_string(),
                affected_paths: affected_paths.clone(),
            },
            MigrationStep {
                step: 4,
                description: "Call-Sites anpassen.".to_string(),
                affected_paths,
            },
        ],
        related_findings: Vec::new(),
    }
}

/// Whether `ty` is one of [`primitive_domain_value_candidates`]'s allowed
/// primitive types (`u8`.."f64"`, `String`, `&str`), matched structurally by
/// the type path's last segment — no type resolution, so a local type alias
/// named e.g. `type String = Foo;` would produce a false positive. This is
/// an accepted Fast-Tier limitation, same in spirit as `crate_for_file`'s
/// path-based crate matching above.
fn primitive_type_name(ty: &syn::Type) -> Option<String> {
    const NUMERIC: &[&str] = &[
        "u8", "u16", "u32", "u64", "usize", "i8", "i16", "i32", "i64", "isize", "f32", "f64",
    ];
    match ty {
        syn::Type::Path(type_path) if type_path.qself.is_none() => {
            let segment = type_path.path.segments.last()?;
            if !matches!(segment.arguments, syn::PathArguments::None) {
                return None;
            }
            let name = segment.ident.to_string();
            if NUMERIC.contains(&name.as_str()) || name == "String" {
                Some(name)
            } else {
                None
            }
        }
        syn::Type::Reference(type_ref) => match &*type_ref.elem {
            syn::Type::Path(type_path) if type_path.qself.is_none() => {
                let segment = type_path.path.segments.last()?;
                if matches!(segment.arguments, syn::PathArguments::None) && segment.ident == "str" {
                    Some("&str".to_string())
                } else {
                    None
                }
            }
            _ => None,
        },
        _ => None,
    }
}

/// Collects [`SignatureParamFact`]s from `pub fn` items (free functions and
/// `impl` methods) in one source file.
struct PrimitiveDomainValueVisitor<'a> {
    file: &'a Path,
    self_type: Option<String>,
    facts: Vec<SignatureParamFact>,
}

impl PrimitiveDomainValueVisitor<'_> {
    fn record_fn(&mut self, name: &str, sig: &syn::Signature, block: &syn::Block) {
        let item_path = match &self.self_type {
            Some(self_type) => format!("{self_type}::{name}"),
            None => name.to_string(),
        };
        for input in &sig.inputs {
            let syn::FnArg::Typed(pat_type) = input else {
                continue;
            };
            let syn::Pat::Ident(pat_ident) = pat_type.pat.as_ref() else {
                continue;
            };
            let Some(type_name) = primitive_type_name(&pat_type.ty) else {
                continue;
            };
            let param = pat_ident.ident.to_string();
            let has_guard = body_has_validation_guard_for(block, &param);
            self.facts.push(SignatureParamFact {
                file: self.file.to_path_buf(),
                item_path: item_path.clone(),
                param,
                type_name,
                has_guard,
            });
        }
    }
}

impl<'ast> Visit<'ast> for PrimitiveDomainValueVisitor<'_> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if matches!(node.vis, syn::Visibility::Public(_)) {
            self.record_fn(&node.sig.ident.to_string(), &node.sig, &node.block);
        }
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        use quote::ToTokens;
        let previous = self
            .self_type
            .replace(node.self_ty.to_token_stream().to_string());
        syn::visit::visit_item_impl(self, node);
        self.self_type = previous;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if matches!(node.vis, syn::Visibility::Public(_)) {
            self.record_fn(&node.sig.ident.to_string(), &node.sig, &node.block);
        }
        syn::visit::visit_impl_item_fn(self, node);
    }
}

/// Whether `expr` references identifier `ident` anywhere within it (used to
/// check that a validation guard's condition actually mentions the
/// parameter in question, not just any `if`/`assert!`).
fn expr_references_ident(expr: &syn::Expr, ident: &str) -> bool {
    struct Finder<'a> {
        ident: &'a str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for Finder<'_> {
        fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
            if node.path.is_ident(self.ident) {
                self.found = true;
            }
            syn::visit::visit_expr_path(self, node);
        }
    }
    let mut finder = Finder {
        ident,
        found: false,
    };
    finder.visit_expr(expr);
    finder.found
}

/// Whether `tokens` contains identifier `ident` as a token anywhere,
/// including inside nested groups (used for `assert!(...)` macro arguments,
/// which `syn` only exposes as an opaque `TokenStream`).
fn tokens_reference_ident(tokens: &proc_macro2::TokenStream, ident: &str) -> bool {
    tokens.clone().into_iter().any(|tree| match tree {
        proc_macro2::TokenTree::Ident(node) => node == ident,
        proc_macro2::TokenTree::Group(group) => tokens_reference_ident(&group.stream(), ident),
        _ => false,
    })
}

/// Whether `block` contains a `return Err(...)` or a `panic!(...)` call
/// anywhere within it (used as the then-branch check for an `if`-shaped
/// validation guard).
fn block_leads_to_error_path(block: &syn::Block) -> bool {
    struct Finder {
        found: bool,
    }
    impl<'ast> Visit<'ast> for Finder {
        fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
            if node.expr.as_deref().is_some_and(is_err_call) {
                self.found = true;
            }
            syn::visit::visit_expr_return(self, node);
        }

        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            if node.path.is_ident("panic") {
                self.found = true;
            }
            syn::visit::visit_macro(self, node);
        }
    }
    let mut finder = Finder { found: false };
    finder.visit_block(block);
    finder.found
}

/// Whether `expr` is a call whose callee path ends in the segment `Err`
/// (covers both bare `Err(...)` and a qualified `Result::Err(...)`).
fn is_err_call(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Call(call) => matches!(
            call.func.as_ref(),
            syn::Expr::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident == "Err")
        ),
        _ => false,
    }
}

/// Whether `block` (a function body) contains a validation guard for
/// `param` — see [`primitive_domain_value_candidates`]'s signal 2.
fn body_has_validation_guard_for(block: &syn::Block, param: &str) -> bool {
    struct GuardVisitor<'a> {
        param: &'a str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for GuardVisitor<'_> {
        fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
            if expr_references_ident(&node.cond, self.param)
                && block_leads_to_error_path(&node.then_branch)
            {
                self.found = true;
            }
            syn::visit::visit_expr_if(self, node);
        }

        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            if node.path.is_ident("assert") && tokens_reference_ident(&node.tokens, self.param) {
                self.found = true;
            }
            syn::visit::visit_macro(self, node);
        }
    }
    let mut visitor = GuardVisitor {
        param,
        found: false,
    };
    visitor.visit_block(block);
    visitor.found
}

/// `boolean-state-cluster` (todo.md §16.3): several bool values are passed
/// around together; combinations of them are checked or guarded against
/// repeatedly.
///
/// **This is a deliberately narrower, Fast-Tier-reachable subset of the full
/// rule from todo.md §16.3** (which is listed there as "Deep" tier), and it
/// is scoped to a single function rather than cross-call-site — the full
/// rule can aggregate evidence about how bool parameters are combined
/// *across* call sites; this implementation only looks within one function
/// body:
///
/// 1. **Primary** — a `fn`/`pub fn` (including a `pub fn new` constructor)
///    has at least three `bool`-typed parameters.
/// 2. **Independent** — the function body contains a condition or `match`
///    that combines at least two of those bool parameters together in one
///    condition (e.g. `if a && b`, `if a && !b`, `match (a, b) { ... }`,
///    `if a || b`) — evidence that combinations are actually checked, not
///    just that several bools happen to be parameters.
///
/// Only functions satisfying both produce a candidate — exactly one per
/// function, scoped to that function rather than the whole crate (unlike
/// `primitive-domain-value`, since the finding here is local to one
/// function).
fn boolean_state_cluster_candidates(workspace: &Workspace) -> Vec<PatternCandidate> {
    let mut candidates = Vec::new();
    for krate in &workspace.crates {
        for source in &krate.source_files {
            let Ok(text) = std::fs::read_to_string(&source.path) else {
                continue;
            };
            let Ok(ast) = syn::parse_file(&text) else {
                continue;
            };
            let mut visitor = BooleanStateClusterVisitor {
                file: &source.path,
                self_type: None,
                facts: Vec::new(),
            };
            visitor.visit_file(&ast);
            for fact in visitor.facts {
                candidates.push(build_boolean_state_cluster_candidate(krate, &fact));
            }
        }
    }
    candidates
}

/// One function whose signature/body satisfy both
/// [`boolean_state_cluster_candidates`] signals.
struct BoolClusterFact {
    file: PathBuf,
    item_path: String,
    bool_params: BTreeSet<String>,
    combo_hits: Vec<String>,
}

fn build_boolean_state_cluster_candidate(
    krate: &CrateInfo,
    fact: &BoolClusterFact,
) -> PatternCandidate {
    let scope = CodeScope {
        krate: krate.name.clone(),
        modules: vec![fact.item_path.clone()],
    };

    let location = EvidenceLocation {
        file: fact.file.clone(),
        item_path: Some(fact.item_path.clone()),
    };

    let bool_params: Vec<&String> = fact.bool_params.iter().collect();
    let primary = Evidence {
        description: format!(
            "`{}` has {} `bool`-typed parameters: {}.",
            fact.item_path,
            fact.bool_params.len(),
            bool_params
                .iter()
                .map(|name| name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        locations: vec![location.clone()],
    };
    let independent = Evidence {
        description: format!(
            "The function body combines at least two of these bool parameters together in a \
             condition, e.g. `{}`.",
            fact.combo_hits.join("`, `")
        ),
        locations: vec![location],
    };

    let evidence_identities: Vec<String> = std::iter::once(fact.item_path.clone())
        .chain(fact.bool_params.iter().cloned())
        .chain(fact.combo_hits.iter().cloned())
        .collect();
    let id = PatternCandidateId::compute(RustPattern::OptionsStruct, &scope, &evidence_identities);

    PatternCandidate {
        id,
        pattern: RustPattern::OptionsStruct,
        scope,
        evidence: CorroboratedEvidence {
            primary,
            independent,
            additional: Vec::new(),
        },
        preconditions: vec![Precondition {
            description: format!(
                "`{}` nimmt mehrere Bool-Parameter entgegen und prüft mindestens eine \
                 Kombination davon gemeinsam im Funktionskörper.",
                fact.item_path
            ),
        }],
        contraindications: vec![
            Contraindication {
                description: "Wenige, klar benannte, unabhängig verwendete Bool-Flags können \
                    lesbarer sein als ein zusätzlicher Enum-/Options-Typ."
                    .to_string(),
            },
            Contraindication {
                description: "Wenn die Kombinationsprüfung nur eine einmalige \
                    Eingabevalidierung ist (kein wiederholtes Muster), kann ein zusätzlicher Typ \
                    Overkill sein."
                    .to_string(),
            },
        ],
        migration: vec![
            MigrationStep {
                step: 1,
                description: "Gültige Optionen/Zustände benennen (Options-Struct vs. \
                    Zustands-Enum, je nach Anzahl gültiger Kombinationen)."
                    .to_string(),
                affected_paths: Vec::new(),
            },
            MigrationStep {
                step: 2,
                description: "Den gewählten Typ definieren.".to_string(),
                affected_paths: Vec::new(),
            },
            MigrationStep {
                step: 3,
                description: "Konstruktor-/Funktionsparameterliste ersetzen.".to_string(),
                affected_paths: vec![fact.file.clone()],
            },
            MigrationStep {
                step: 4,
                description: "Call-Sites aktualisieren.".to_string(),
                affected_paths: vec![fact.file.clone()],
            },
        ],
        related_findings: Vec::new(),
    }
}

/// Whether `ty` is `bool`, matched structurally (same caveat as
/// [`primitive_type_name`]: no type resolution).
fn is_bool_type(ty: &syn::Type) -> bool {
    matches!(
        ty,
        syn::Type::Path(type_path)
            if type_path.qself.is_none()
                && type_path.path.segments.last().is_some_and(|segment| {
                    segment.ident == "bool" && matches!(segment.arguments, syn::PathArguments::None)
                })
    )
}

/// Collects [`BoolClusterFact`]s from `fn` items (free functions and `impl`
/// methods, any visibility) in one source file.
struct BooleanStateClusterVisitor<'a> {
    file: &'a Path,
    self_type: Option<String>,
    facts: Vec<BoolClusterFact>,
}

impl BooleanStateClusterVisitor<'_> {
    fn record_fn(&mut self, name: &str, sig: &syn::Signature, block: &syn::Block) {
        let item_path = match &self.self_type {
            Some(self_type) => format!("{self_type}::{name}"),
            None => name.to_string(),
        };
        let bool_params: BTreeSet<String> = sig
            .inputs
            .iter()
            .filter_map(|input| {
                let syn::FnArg::Typed(pat_type) = input else {
                    return None;
                };
                if !is_bool_type(&pat_type.ty) {
                    return None;
                }
                let syn::Pat::Ident(pat_ident) = pat_type.pat.as_ref() else {
                    return None;
                };
                Some(pat_ident.ident.to_string())
            })
            .collect();
        if bool_params.len() < 3 {
            return;
        }
        let combo_hits = body_boolean_combo_hits(block, &bool_params);
        if combo_hits.is_empty() {
            return;
        }
        self.facts.push(BoolClusterFact {
            file: self.file.to_path_buf(),
            item_path,
            bool_params,
            combo_hits,
        });
    }
}

impl<'ast> Visit<'ast> for BooleanStateClusterVisitor<'_> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.record_fn(&node.sig.ident.to_string(), &node.sig, &node.block);
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        use quote::ToTokens;
        let previous = self
            .self_type
            .replace(node.self_ty.to_token_stream().to_string());
        syn::visit::visit_item_impl(self, node);
        self.self_type = previous;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.record_fn(&node.sig.ident.to_string(), &node.sig, &node.block);
        syn::visit::visit_impl_item_fn(self, node);
    }
}

/// The subset of `params` referenced anywhere within `expr` (used to check
/// how many distinct bool parameters a condition/match-scrutinee combines).
fn referenced_params_in_expr(expr: &syn::Expr, params: &BTreeSet<String>) -> BTreeSet<String> {
    struct Collector<'a> {
        params: &'a BTreeSet<String>,
        found: BTreeSet<String>,
    }
    impl<'ast> Visit<'ast> for Collector<'_> {
        fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
            if let Some(ident) = node.path.get_ident() {
                let name = ident.to_string();
                if self.params.contains(&name) {
                    self.found.insert(name);
                }
            }
            syn::visit::visit_expr_path(self, node);
        }
    }
    let mut collector = Collector {
        params,
        found: BTreeSet::new(),
    };
    collector.visit_expr(expr);
    collector.found
}

/// Rendered source text of every `if`/`match` in `block` whose
/// condition/scrutinee combines at least two of `bool_params` — see
/// [`boolean_state_cluster_candidates`]'s signal 2.
fn body_boolean_combo_hits(block: &syn::Block, bool_params: &BTreeSet<String>) -> Vec<String> {
    use quote::ToTokens;

    struct ComboVisitor<'a> {
        bool_params: &'a BTreeSet<String>,
        hits: Vec<String>,
    }
    impl<'ast> Visit<'ast> for ComboVisitor<'_> {
        fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
            if referenced_params_in_expr(&node.cond, self.bool_params).len() >= 2 {
                self.hits.push(node.cond.to_token_stream().to_string());
            }
            syn::visit::visit_expr_if(self, node);
        }

        fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
            if referenced_params_in_expr(&node.expr, self.bool_params).len() >= 2 {
                self.hits.push(node.expr.to_token_stream().to_string());
            }
            syn::visit::visit_expr_match(self, node);
        }
    }
    let mut visitor = ComboVisitor {
        bool_params,
        hits: Vec::new(),
    };
    visitor.visit_block(block);
    visitor.hits
}

/// `public-invariant-bypass` (todo.md §16.3): public fields are freely
/// writable, but consumers assume a value range or a combination of fields
/// holds together.
///
/// **This is a deliberately narrower, Fast-Tier-reachable subset of the full
/// rule from todo.md §16.3** (which is listed there as "Deep" tier) —
/// deliberately *without* the full rule's consumer-side analysis. This
/// implementation only looks at:
///
/// 1. **Primary (structural)** — a `pub struct` with ≥2 `pub` fields, without
///    a `#[non_exhaustive]` attribute, in the same crate.
/// 2. **Independent (control flow, same crate)** — at least one
///    constructor-shaped function for that struct type (a `pub fn` whose
///    return type is `Self`/the struct name, optionally wrapped in
///    `Result<..>`) contains a condition that jointly validates ≥2 of the
///    struct's `pub` fields — matched via parameter names that equal field
///    names (same name-matching heuristic as `boolean-state-cluster`) — and
///    whose then-branch leads to `Err(...)`/`panic!(...)`, or an
///    `assert!(...)` referencing ≥2 of those parameters.
///
/// Only structs satisfying both produce a candidate — exactly one per
/// struct, referencing every contributing constructor.
fn public_invariant_bypass_candidates(workspace: &Workspace) -> Vec<PatternCandidate> {
    let mut candidates = Vec::new();
    for krate in &workspace.crates {
        let mut structs: BTreeMap<String, PubStructFact> = BTreeMap::new();
        for source in &krate.source_files {
            let Ok(text) = std::fs::read_to_string(&source.path) else {
                continue;
            };
            let Ok(ast) = syn::parse_file(&text) else {
                continue;
            };
            let mut visitor = PubStructVisitor {
                file: &source.path,
                structs: BTreeMap::new(),
            };
            visitor.visit_file(&ast);
            structs.extend(visitor.structs);
        }
        if structs.is_empty() {
            continue;
        }

        let mut constructor_hits: BTreeMap<String, Vec<ConstructorFact>> = BTreeMap::new();
        for source in &krate.source_files {
            let Ok(text) = std::fs::read_to_string(&source.path) else {
                continue;
            };
            let Ok(ast) = syn::parse_file(&text) else {
                continue;
            };
            let mut visitor = ConstructorVisitor {
                file: &source.path,
                self_type: None,
                structs: &structs,
                hits: BTreeMap::new(),
            };
            visitor.visit_file(&ast);
            for (name, mut facts) in visitor.hits {
                constructor_hits.entry(name).or_default().append(&mut facts);
            }
        }

        for (name, fact) in &structs {
            let Some(ctor_facts) = constructor_hits.get(name) else {
                continue;
            };
            if ctor_facts.is_empty() {
                continue;
            }
            candidates.push(build_public_invariant_bypass_candidate(
                krate, fact, ctor_facts,
            ));
        }
    }
    candidates
}

/// A crate-local `pub struct` with ≥2 `pub` fields and no `#[non_exhaustive]`
/// attribute (see [`public_invariant_bypass_candidates`]'s signal 1).
struct PubStructFact {
    file: PathBuf,
    name: String,
    fields: BTreeSet<String>,
}

/// Whether any attribute in `attrs` is `#[non_exhaustive]`.
fn has_non_exhaustive_attr(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .any(|attr| attr.path().is_ident("non_exhaustive"))
}

/// Collects [`PubStructFact`]s from `pub struct` items in one source file.
struct PubStructVisitor<'a> {
    file: &'a Path,
    structs: BTreeMap<String, PubStructFact>,
}

impl<'ast> Visit<'ast> for PubStructVisitor<'_> {
    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        if matches!(node.vis, syn::Visibility::Public(_)) && !has_non_exhaustive_attr(&node.attrs) {
            let fields: BTreeSet<String> = node
                .fields
                .iter()
                .filter(|field| matches!(field.vis, syn::Visibility::Public(_)))
                .filter_map(|field| field.ident.as_ref().map(ToString::to_string))
                .collect();
            if fields.len() >= 2 {
                let name = node.ident.to_string();
                self.structs.insert(
                    name.clone(),
                    PubStructFact {
                        file: self.file.to_path_buf(),
                        name,
                        fields,
                    },
                );
            }
        }
        syn::visit::visit_item_struct(self, node);
    }
}

/// One constructor-shaped function corroborating a [`PubStructFact`] (see
/// [`public_invariant_bypass_candidates`]'s signal 2).
struct ConstructorFact {
    file: PathBuf,
    item_path: String,
    hits: Vec<String>,
}

/// Collects [`ConstructorFact`]s, keyed by struct name, from `pub fn` items
/// (free functions and `impl` methods) in one source file whose return type
/// resolves to a struct already recorded in `structs`.
struct ConstructorVisitor<'a> {
    file: &'a Path,
    self_type: Option<String>,
    structs: &'a BTreeMap<String, PubStructFact>,
    hits: BTreeMap<String, Vec<ConstructorFact>>,
}

impl ConstructorVisitor<'_> {
    fn record_fn(&mut self, name: &str, sig: &syn::Signature, block: &syn::Block) {
        let syn::ReturnType::Type(_, ty) = &sig.output else {
            return;
        };
        let Some(struct_name) = resolved_struct_name(ty, self.self_type.as_deref()) else {
            return;
        };
        let Some(fact) = self.structs.get(&struct_name) else {
            return;
        };
        let param_names: BTreeSet<String> = sig
            .inputs
            .iter()
            .filter_map(|input| {
                let syn::FnArg::Typed(pat_type) = input else {
                    return None;
                };
                let syn::Pat::Ident(pat_ident) = pat_type.pat.as_ref() else {
                    return None;
                };
                Some(pat_ident.ident.to_string())
            })
            .collect();
        let matching_params: BTreeSet<String> =
            param_names.intersection(&fact.fields).cloned().collect();
        if matching_params.len() < 2 {
            return;
        }
        let hits = constructor_combo_hits(block, &matching_params);
        if hits.is_empty() {
            return;
        }
        let item_path = match &self.self_type {
            Some(self_type) => format!("{self_type}::{name}"),
            None => name.to_string(),
        };
        self.hits
            .entry(struct_name)
            .or_default()
            .push(ConstructorFact {
                file: self.file.to_path_buf(),
                item_path,
                hits,
            });
    }
}

impl<'ast> Visit<'ast> for ConstructorVisitor<'_> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if matches!(node.vis, syn::Visibility::Public(_)) {
            self.record_fn(&node.sig.ident.to_string(), &node.sig, &node.block);
        }
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        use quote::ToTokens;
        let previous = self
            .self_type
            .replace(node.self_ty.to_token_stream().to_string());
        syn::visit::visit_item_impl(self, node);
        self.self_type = previous;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if matches!(node.vis, syn::Visibility::Public(_)) {
            self.record_fn(&node.sig.ident.to_string(), &node.sig, &node.block);
        }
        syn::visit::visit_impl_item_fn(self, node);
    }
}

/// The struct name `ty` resolves to, if any: `Self` (resolved via
/// `self_type`, i.e. only within an `impl` block), the struct name directly,
/// or one level of `Result<T, _>` unwrapped around either — matched
/// structurally, no type resolution (same caveat as [`primitive_type_name`]).
fn resolved_struct_name(ty: &syn::Type, self_type: Option<&str>) -> Option<String> {
    let syn::Type::Path(type_path) = ty else {
        return None;
    };
    let segment = type_path.path.segments.last()?;
    let name = segment.ident.to_string();
    if name == "Self" {
        return self_type.map(str::to_string);
    }
    if name == "Result"
        && let syn::PathArguments::AngleBracketed(generics) = &segment.arguments
        && let Some(syn::GenericArgument::Type(inner)) = generics.args.first()
    {
        return resolved_struct_name(inner, self_type);
    }
    Some(name)
}

/// Rendered source text of every `if`/`assert!` in `block` that jointly
/// validates ≥2 of `matching_params` — see
/// [`public_invariant_bypass_candidates`]'s signal 2.
fn constructor_combo_hits(block: &syn::Block, matching_params: &BTreeSet<String>) -> Vec<String> {
    use quote::ToTokens;

    struct ComboVisitor<'a> {
        matching_params: &'a BTreeSet<String>,
        hits: Vec<String>,
    }
    impl<'ast> Visit<'ast> for ComboVisitor<'_> {
        fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
            if referenced_params_in_expr(&node.cond, self.matching_params).len() >= 2
                && block_leads_to_error_path(&node.then_branch)
            {
                self.hits.push(node.cond.to_token_stream().to_string());
            }
            syn::visit::visit_expr_if(self, node);
        }

        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            if node.path.is_ident("assert")
                && tokens_reference_at_least_two_idents(&node.tokens, self.matching_params)
            {
                self.hits.push(node.tokens.to_string());
            }
            syn::visit::visit_macro(self, node);
        }
    }
    let mut visitor = ComboVisitor {
        matching_params,
        hits: Vec::new(),
    };
    visitor.visit_block(block);
    visitor.hits
}

/// Whether `tokens` references at least two distinct identifiers from
/// `idents` anywhere, including inside nested groups (used for `assert!`
/// macro arguments, same rationale as [`tokens_reference_ident`]).
fn tokens_reference_at_least_two_idents(
    tokens: &proc_macro2::TokenStream,
    idents: &BTreeSet<String>,
) -> bool {
    fn collect(
        tokens: proc_macro2::TokenStream,
        idents: &BTreeSet<String>,
        found: &mut BTreeSet<String>,
    ) {
        for tree in tokens {
            match tree {
                proc_macro2::TokenTree::Ident(node) => {
                    let name = node.to_string();
                    if idents.contains(&name) {
                        found.insert(name);
                    }
                }
                proc_macro2::TokenTree::Group(group) => collect(group.stream(), idents, found),
                _ => {}
            }
        }
    }
    let mut found = BTreeSet::new();
    collect(tokens.clone(), idents, &mut found);
    found.len() >= 2
}

fn build_public_invariant_bypass_candidate(
    krate: &CrateInfo,
    fact: &PubStructFact,
    ctor_facts: &[ConstructorFact],
) -> PatternCandidate {
    let scope = CodeScope {
        krate: krate.name.clone(),
        modules: vec![fact.name.clone()],
    };

    let primary_locations: Vec<EvidenceLocation> = fact
        .fields
        .iter()
        .map(|field| EvidenceLocation {
            file: fact.file.clone(),
            item_path: Some(format!("{}::{field}", fact.name)),
        })
        .collect();
    let field_list: Vec<&str> = fact.fields.iter().map(String::as_str).collect();

    let primary = Evidence {
        description: format!(
            "`pub struct {}` in crate `{}` has {} `pub` field(s) ({}) and carries no \
             `#[non_exhaustive]` attribute.",
            fact.name,
            krate.name,
            fact.fields.len(),
            field_list.join(", ")
        ),
        locations: primary_locations,
    };

    let mut independent_locations: Vec<EvidenceLocation> = ctor_facts
        .iter()
        .map(|ctor| EvidenceLocation {
            file: ctor.file.clone(),
            item_path: Some(ctor.item_path.clone()),
        })
        .collect();
    independent_locations.sort_by(|a, b| (&a.file, &a.item_path).cmp(&(&b.file, &b.item_path)));

    let combo_texts: Vec<&str> = ctor_facts
        .iter()
        .flat_map(|ctor| ctor.hits.iter())
        .map(String::as_str)
        .collect();
    let independent = Evidence {
        description: format!(
            "At least one constructor for `{}` already validates a combination of ≥2 of these \
             `pub` fields together, e.g. `{}`.",
            fact.name,
            combo_texts.join("`, `")
        ),
        locations: independent_locations,
    };

    let evidence_identities: Vec<String> = std::iter::once(fact.name.clone())
        .chain(fact.fields.iter().cloned())
        .chain(ctor_facts.iter().map(|ctor| ctor.item_path.clone()))
        .collect();
    let id =
        PatternCandidateId::compute(RustPattern::SmartConstructor, &scope, &evidence_identities);

    let mut affected_paths: Vec<PathBuf> = std::iter::once(fact.file.clone())
        .chain(ctor_facts.iter().map(|ctor| ctor.file.clone()))
        .collect();
    affected_paths.sort();
    affected_paths.dedup();

    PatternCandidate {
        id,
        pattern: RustPattern::SmartConstructor,
        scope,
        evidence: CorroboratedEvidence {
            primary,
            independent,
            additional: Vec::new(),
        },
        preconditions: vec![Precondition {
            description: format!(
                "`{}` hat mindestens zwei öffentliche Felder und mindestens ein Konstruktor \
                 validiert bereits eine Kombination davon.",
                fact.name
            ),
        }],
        contraindications: vec![
            Contraindication {
                description: "Wenn der Struct primär als reine Datenhülle ohne Invarianten \
                    außerhalb des Konstruktors gedacht ist, kann öffentlicher Feldzugriff bewusst \
                    sein."
                    .to_string(),
            },
            Contraindication {
                description: "Private Felder erzwingen Getter-/Setter-Boilerplate, was bei \
                    internen/Test-only-Structs mehr kostet als nützt."
                    .to_string(),
            },
        ],
        migration: vec![
            MigrationStep {
                step: 1,
                description: "Felder privat machen.".to_string(),
                affected_paths: vec![fact.file.clone()],
            },
            MigrationStep {
                step: 2,
                description:
                    "Bestehenden Konstruktor als einzigen Erzeugungsweg belassen/ausbauen."
                        .to_string(),
                affected_paths: Vec::new(),
            },
            MigrationStep {
                step: 3,
                description: "Falls Änderungen nach Konstruktion nötig sind, validierte Setter \
                    statt direkter Feldzuweisung ergänzen."
                    .to_string(),
                affected_paths: Vec::new(),
            },
            MigrationStep {
                step: 4,
                description: "Call-Sites, die Struct-Update-Syntax nutzen, anpassen.".to_string(),
                affected_paths,
            },
        ],
        related_findings: Vec::new(),
    }
}

/// `manual-resource-lifecycle` (todo.md §16.3): recurring acquire/release-,
/// register/unregister-, or setup/cleanup pairs on several control-flow
/// paths.
///
/// **This is a deliberately narrower, Fast-Tier-reachable subset of the full
/// rule from todo.md §16.3** (which is listed there as "Deep" tier), with
/// especially strong contraindications: todo.md §16.4 only allows this
/// recommendation "wenn Besitz und Lebensdauer der Ressource eindeutig an
/// einen Guard gebunden werden können" — this Fast-Tier heuristic cannot
/// prove that, and the contraindications say so explicitly. This
/// implementation only looks at:
///
/// 1. **Primary (structural)** — within one function, both a call whose
///    ident matches a fixed "acquire" name pattern (`register`, `acquire`,
///    `open`, `lock`, `begin`, `start`, `connect`, `subscribe`) and a call
///    matching the corresponding "release" pattern (`unregister`, `release`,
///    `close`, `unlock`, `end`, `stop`, `disconnect`, `unsubscribe`) appear —
///    detected purely by call identifier, no type resolution. This can
///    falsely couple unrelated calls that merely share a common name.
/// 2. **Independent (crate-wide)** — the entire crate contains no
///    `impl Drop for ...` block at all, i.e. no evidence this codebase
///    already uses RAII guards as a pattern.
///
/// Only when both signals hold does exactly one candidate per crate emerge,
/// referencing every contributing function.
fn manual_resource_lifecycle_candidates(workspace: &Workspace) -> Vec<PatternCandidate> {
    let mut candidates = Vec::new();
    for krate in &workspace.crates {
        let mut has_drop_impl = false;
        let mut hits: Vec<EvidenceLocation> = Vec::new();
        for source in &krate.source_files {
            let Ok(text) = std::fs::read_to_string(&source.path) else {
                continue;
            };
            let Ok(ast) = syn::parse_file(&text) else {
                continue;
            };
            if file_has_drop_impl(&ast) {
                has_drop_impl = true;
            }
            let mut visitor = ResourceLifecycleVisitor {
                file: &source.path,
                self_type: None,
                hits: Vec::new(),
            };
            visitor.visit_file(&ast);
            hits.append(&mut visitor.hits);
        }
        if has_drop_impl || hits.is_empty() {
            continue;
        }
        candidates.push(build_manual_resource_lifecycle_candidate(krate, &hits));
    }
    candidates
}

const ACQUIRE_CALL_NAMES: &[&str] = &[
    "register",
    "acquire",
    "open",
    "lock",
    "begin",
    "start",
    "connect",
    "subscribe",
];

const RELEASE_CALL_NAMES: &[&str] = &[
    "unregister",
    "release",
    "close",
    "unlock",
    "end",
    "stop",
    "disconnect",
    "unsubscribe",
];

/// Whether `ast` contains an `impl Drop for ...` block anywhere (see
/// [`manual_resource_lifecycle_candidates`]'s signal 2).
fn file_has_drop_impl(ast: &syn::File) -> bool {
    struct DropFinder {
        found: bool,
    }
    impl<'ast> Visit<'ast> for DropFinder {
        fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
            if let Some((_, path, _)) = &node.trait_
                && path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "Drop")
            {
                self.found = true;
            }
            syn::visit::visit_item_impl(self, node);
        }
    }
    let mut finder = DropFinder { found: false };
    finder.visit_file(ast);
    finder.found
}

/// Whether `block` contains at least one call matching
/// [`ACQUIRE_CALL_NAMES`] and at least one call matching
/// [`RELEASE_CALL_NAMES`], by call identifier only.
fn acquire_and_release_calls(block: &syn::Block) -> (bool, bool) {
    struct Finder {
        acquire: bool,
        release: bool,
    }
    impl Finder {
        fn observe(&mut self, name: &str) {
            if ACQUIRE_CALL_NAMES.contains(&name) {
                self.acquire = true;
            }
            if RELEASE_CALL_NAMES.contains(&name) {
                self.release = true;
            }
        }
    }
    impl<'ast> Visit<'ast> for Finder {
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            self.observe(&node.method.to_string());
            syn::visit::visit_expr_method_call(self, node);
        }

        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = node.func.as_ref()
                && let Some(segment) = path.path.segments.last()
            {
                self.observe(&segment.ident.to_string());
            }
            syn::visit::visit_expr_call(self, node);
        }
    }
    let mut finder = Finder {
        acquire: false,
        release: false,
    };
    finder.visit_block(block);
    (finder.acquire, finder.release)
}

/// Collects one [`EvidenceLocation`] per function (free function or `impl`
/// method, any visibility) in one source file whose body contains both an
/// acquire- and a release-shaped call.
struct ResourceLifecycleVisitor<'a> {
    file: &'a Path,
    self_type: Option<String>,
    hits: Vec<EvidenceLocation>,
}

impl ResourceLifecycleVisitor<'_> {
    fn record_fn(&mut self, name: &str, block: &syn::Block) {
        let (has_acquire, has_release) = acquire_and_release_calls(block);
        if !has_acquire || !has_release {
            return;
        }
        let item_path = match &self.self_type {
            Some(self_type) => format!("{self_type}::{name}"),
            None => name.to_string(),
        };
        self.hits.push(EvidenceLocation {
            file: self.file.to_path_buf(),
            item_path: Some(item_path),
        });
    }
}

impl<'ast> Visit<'ast> for ResourceLifecycleVisitor<'_> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.record_fn(&node.sig.ident.to_string(), &node.block);
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        use quote::ToTokens;
        let previous = self
            .self_type
            .replace(node.self_ty.to_token_stream().to_string());
        syn::visit::visit_item_impl(self, node);
        self.self_type = previous;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.record_fn(&node.sig.ident.to_string(), &node.block);
        syn::visit::visit_impl_item_fn(self, node);
    }
}

fn build_manual_resource_lifecycle_candidate(
    krate: &CrateInfo,
    hits: &[EvidenceLocation],
) -> PatternCandidate {
    let mut modules: Vec<String> = hits
        .iter()
        .filter_map(|hit| hit.item_path.clone())
        .collect();
    modules.sort();
    modules.dedup();
    let scope = CodeScope {
        krate: krate.name.clone(),
        modules,
    };

    let mut primary_locations = hits.to_vec();
    primary_locations.sort_by(|a, b| (&a.file, &a.item_path).cmp(&(&b.file, &b.item_path)));

    let primary = Evidence {
        description: format!(
            "{} function(s) in crate `{}` call both an acquire-shaped operation (e.g. \
             `register`/`acquire`/`open`/`lock`/`begin`/`start`/`connect`/`subscribe`) and a \
             release-shaped counterpart (e.g. \
             `unregister`/`release`/`close`/`unlock`/`end`/`stop`/`disconnect`/`unsubscribe`) by \
             call name.",
            hits.len(),
            krate.name
        ),
        locations: primary_locations,
    };
    let independent = Evidence {
        description: format!(
            "Crate `{}` contains no `impl Drop for ...` block anywhere — no evidence this \
             codebase already uses RAII guards as a pattern.",
            krate.name
        ),
        locations: Vec::new(),
    };

    let evidence_identities: Vec<String> = hits
        .iter()
        .map(|hit| {
            format!(
                "{}:{}",
                hit.file.display(),
                hit.item_path.as_deref().unwrap_or("")
            )
        })
        .collect();
    let id = PatternCandidateId::compute(RustPattern::RaiiGuard, &scope, &evidence_identities);

    let mut affected_paths: Vec<PathBuf> = hits.iter().map(|hit| hit.file.clone()).collect();
    affected_paths.sort();
    affected_paths.dedup();

    PatternCandidate {
        id,
        pattern: RustPattern::RaiiGuard,
        scope,
        evidence: CorroboratedEvidence {
            primary,
            independent,
            additional: Vec::new(),
        },
        preconditions: vec![Precondition {
            description: format!(
                "Crate `{}` enthält mindestens ein Acquire-/Release-Aufrufpaar innerhalb einer \
                 Funktion, aber keine `Drop`-Implementierung.",
                krate.name
            ),
        }],
        contraindications: vec![
            Contraindication {
                description: "Diese Heuristik kann nicht belegen, dass Besitz und Lebensdauer \
                    der Ressource eindeutig an einen einzelnen Guard gebunden werden können — das \
                    ist Voraussetzung für einen sinnvollen RAII-Guard, nicht nur Namensähnlichkeit."
                    .to_string(),
            },
            Contraindication {
                description: "Acquire/Release könnten unabhängige, zufällig gleich benannte \
                    Operationen auf unterschiedlichen Objekten sein."
                    .to_string(),
            },
            Contraindication {
                description: "Bei seltener, einmaliger Nutzung kann der Boilerplate eines \
                    eigenen Guard-Typs mehr kosten als eine sorgfältige manuelle Passung."
                    .to_string(),
            },
        ],
        migration: vec![
            MigrationStep {
                step: 1,
                description: "Ressourcentyp und Lebensdauer-Bindung manuell bestätigen (nicht \
                    automatisierbar)."
                    .to_string(),
                affected_paths: Vec::new(),
            },
            MigrationStep {
                step: 2,
                description: "Guard-Struct mit dem Handle als Feld definieren.".to_string(),
                affected_paths: Vec::new(),
            },
            MigrationStep {
                step: 3,
                description: "`Drop::drop` mit der Release-Logik implementieren.".to_string(),
                affected_paths: Vec::new(),
            },
            MigrationStep {
                step: 4,
                description: "Acquire-Stelle so umbauen, dass sie den Guard statt des rohen \
                    Handles zurückgibt."
                    .to_string(),
                affected_paths,
            },
        ],
        related_findings: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{EvidenceClass, Location, OneBasedLine, Origin, Severity};
    use crate::ingest::{SourceFile, SourceKind};
    use crate::test_util::TempDir;

    fn workspace_with_crate(root: PathBuf, files: Vec<PathBuf>) -> Workspace {
        Workspace {
            root: root.clone(),
            crates: vec![CrateInfo {
                name: "fixture".to_string(),
                version: "0.1.0".to_string(),
                manifest_path: root.join("Cargo.toml"),
                root,
                source_files: files
                    .into_iter()
                    .map(|path| SourceFile {
                        path,
                        kind: SourceKind::Authored,
                    })
                    .collect(),
                entry_points: Vec::new(),
                dependencies: Vec::new(),
            }],
        }
    }

    fn catch_all_error_finding(file: &Path, item_path: &str, line: usize) -> Finding {
        Finding::new(
            format!("catch-all-error:{}:{line}:1", file.display()),
            crate::slop::CATCH_ALL_ERROR_RULE,
            Severity::Warn,
            Location {
                file: file.to_path_buf(),
                line: OneBasedLine::new(line).unwrap(),
                item_path: item_path.to_string(),
            },
            EvidenceClass::DerivedFact,
            Origin::Code,
            None,
        )
    }

    /// (a) Two `catch-all-error` findings plus a crate-local typed error ⇒
    /// exactly one candidate, referencing both findings, with both evidence
    /// slots populated.
    #[test]
    fn two_symptoms_plus_a_typed_error_produce_one_candidate() {
        let dir = TempDir::new("pattern-corroborated");
        let boundary = dir.join("boundary.rs");
        std::fs::write(
            &boundary,
            "pub fn a() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }\n\
             pub fn b() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }\n",
        )
        .unwrap();
        let errors = dir.join("errors.rs");
        std::fs::write(&errors, "enum FooError { Bad }\n").unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![boundary.clone(), errors]);
        let findings = vec![
            catch_all_error_finding(&boundary, "a", 1),
            catch_all_error_finding(&boundary, "b", 2),
        ];

        let candidates = analyze_workspace(&workspace, &findings);
        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        assert_eq!(candidate.pattern, RustPattern::DomainError);
        assert_eq!(candidate.scope.krate, "fixture");
        assert_eq!(candidate.related_findings.len(), 2);
        assert!(!candidate.evidence.primary.locations.is_empty());
        assert!(!candidate.evidence.independent.locations.is_empty());
        assert!(candidate.evidence.primary.description.contains('2'));
        assert!(!candidate.contraindications.is_empty());
        assert!(candidate.migration.len() >= 2);
    }

    /// (b) Only one `catch-all-error` finding, even with a typed error
    /// present ⇒ no candidate (a single symptom is not a pattern).
    #[test]
    fn a_single_finding_is_below_threshold() {
        let dir = TempDir::new("pattern-single-finding");
        let boundary = dir.join("boundary.rs");
        std::fs::write(
            &boundary,
            "pub fn a() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }\n",
        )
        .unwrap();
        let errors = dir.join("errors.rs");
        std::fs::write(&errors, "enum FooError { Bad }\n").unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![boundary.clone(), errors]);
        let findings = vec![catch_all_error_finding(&boundary, "a", 1)];

        assert!(analyze_workspace(&workspace, &findings).is_empty());
    }

    /// (c) Two `catch-all-error` findings but no crate-local typed error ⇒
    /// no candidate (only one independent signal, not corroborated).
    #[test]
    fn two_findings_without_a_typed_error_are_not_corroborated() {
        let dir = TempDir::new("pattern-uncorroborated");
        let boundary = dir.join("boundary.rs");
        std::fs::write(
            &boundary,
            "pub fn a() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }\n\
             pub fn b() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![boundary.clone()]);
        let findings = vec![
            catch_all_error_finding(&boundary, "a", 1),
            catch_all_error_finding(&boundary, "b", 2),
        ];

        assert!(analyze_workspace(&workspace, &findings).is_empty());
    }

    /// `impl ... Error for ...` alone (no `Error`-named enum, no derive) is
    /// enough for the independent signal.
    #[test]
    fn a_manual_error_trait_impl_counts_as_the_independent_signal() {
        let dir = TempDir::new("pattern-manual-impl");
        let boundary = dir.join("boundary.rs");
        std::fs::write(
            &boundary,
            "pub fn a() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }\n\
             pub fn b() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }\n",
        )
        .unwrap();
        let errors = dir.join("errors.rs");
        std::fs::write(
            &errors,
            "struct Oops;\n\
             impl std::fmt::Display for Oops { fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { Ok(()) } }\n\
             impl std::error::Error for Oops {}\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![boundary.clone(), errors]);
        let findings = vec![
            catch_all_error_finding(&boundary, "a", 1),
            catch_all_error_finding(&boundary, "b", 2),
        ];

        assert_eq!(analyze_workspace(&workspace, &findings).len(), 1);
    }

    /// The id is deterministic across repeated aggregation runs over the
    /// same inputs.
    #[test]
    fn candidate_id_is_deterministic() {
        let dir = TempDir::new("pattern-deterministic-id");
        let boundary = dir.join("boundary.rs");
        std::fs::write(
            &boundary,
            "pub fn a() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }\n\
             pub fn b() -> Result<(), Box<dyn std::error::Error>> { Ok(()) }\n",
        )
        .unwrap();
        let errors = dir.join("errors.rs");
        std::fs::write(&errors, "enum FooError { Bad }\n").unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![boundary.clone(), errors]);
        let findings = vec![
            catch_all_error_finding(&boundary, "a", 1),
            catch_all_error_finding(&boundary, "b", 2),
        ];

        let first = analyze_workspace(&workspace, &findings);
        let second = analyze_workspace(&workspace, &findings);
        assert_eq!(first[0].id, second[0].id);
    }

    /// `primitive-domain-value` (a): two `pub fn` signatures sharing a
    /// (parameter name, type) pair, one of them guarding the parameter with
    /// an early `return Err(...)` ⇒ one candidate with both evidence slots
    /// populated by the correct fundstellen.
    #[test]
    fn primitive_domain_value_two_signatures_plus_a_guard_produce_one_candidate() {
        let dir = TempDir::new("pattern-primitive-corroborated");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub fn set_a(threshold: u32) {}\n\
             pub fn set_b(threshold: u32) -> Result<(), String> {\n\
             \x20   if threshold > 100 {\n\
             \x20       return Err(\"too big\".to_string());\n\
             \x20   }\n\
             \x20   Ok(())\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let candidates = analyze_workspace(&workspace, &[]);

        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        assert_eq!(candidate.pattern, RustPattern::ValidatedNewtype);
        assert_eq!(candidate.scope.krate, "fixture");
        assert_eq!(candidate.evidence.primary.locations.len(), 2);
        assert_eq!(candidate.evidence.independent.locations.len(), 1);
        assert_eq!(
            candidate.evidence.independent.locations[0]
                .item_path
                .as_deref(),
            Some("set_b")
        );
        assert!(!candidate.contraindications.is_empty());
        assert!(candidate.migration.len() >= 2);
    }

    /// `primitive-domain-value` (b): only one signature, even with a guard
    /// ⇒ no candidate (a single occurrence is not a pattern).
    #[test]
    fn primitive_domain_value_single_signature_is_below_threshold() {
        let dir = TempDir::new("pattern-primitive-single");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub fn set_a(threshold: u32) -> Result<(), String> {\n\
             \x20   if threshold > 100 {\n\
             \x20       return Err(\"too big\".to_string());\n\
             \x20   }\n\
             \x20   Ok(())\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        assert!(analyze_workspace(&workspace, &[]).is_empty());
    }

    /// `primitive-domain-value` (c): two signatures sharing the pair, but no
    /// validation guard anywhere ⇒ no candidate (only one signal).
    #[test]
    fn primitive_domain_value_without_any_guard_is_not_corroborated() {
        let dir = TempDir::new("pattern-primitive-unguarded");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub fn set_a(threshold: u32) {}\n\
             pub fn set_b(threshold: u32) {}\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        assert!(analyze_workspace(&workspace, &[]).is_empty());
    }

    /// `boolean-state-cluster` (a): a function with three bool parameters
    /// and a condition combining two of them ⇒ one candidate.
    #[test]
    fn boolean_cluster_three_bools_plus_a_combined_condition_produce_one_candidate() {
        let dir = TempDir::new("pattern-bool-corroborated");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub fn configure(verbose: bool, strict: bool, dry_run: bool) {\n\
             \x20   if verbose && strict {\n\
             \x20       do_thing();\n\
             \x20   }\n\
             \x20   let _ = dry_run;\n\
             }\n\
             fn do_thing() {}\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let candidates = analyze_workspace(&workspace, &[]);

        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        assert_eq!(candidate.pattern, RustPattern::OptionsStruct);
        assert_eq!(candidate.scope.krate, "fixture");
        assert_eq!(candidate.scope.modules, vec!["configure".to_string()]);
        assert!(!candidate.contraindications.is_empty());
    }

    /// `boolean-state-cluster` (b): three bool parameters, but only
    /// independent single-flag checks, never combined ⇒ no candidate.
    #[test]
    fn boolean_cluster_without_a_combined_condition_is_not_corroborated() {
        let dir = TempDir::new("pattern-bool-independent-checks");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub fn configure(verbose: bool, strict: bool, dry_run: bool) {\n\
             \x20   if verbose {\n\
             \x20       do_thing();\n\
             \x20   }\n\
             \x20   if strict {\n\
             \x20       do_thing();\n\
             \x20   }\n\
             \x20   if dry_run {\n\
             \x20       do_thing();\n\
             \x20   }\n\
             }\n\
             fn do_thing() {}\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        assert!(analyze_workspace(&workspace, &[]).is_empty());
    }

    /// `boolean-state-cluster` (c): only two bool parameters, even with a
    /// combined condition ⇒ no candidate (threshold of three not reached).
    #[test]
    fn boolean_cluster_with_only_two_bools_is_below_threshold() {
        let dir = TempDir::new("pattern-bool-below-threshold");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub fn configure(verbose: bool, strict: bool) {\n\
             \x20   if verbose && strict {\n\
             \x20       do_thing();\n\
             \x20   }\n\
             }\n\
             fn do_thing() {}\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        assert!(analyze_workspace(&workspace, &[]).is_empty());
    }

    /// `public-invariant-bypass` (a): a `pub struct` with two `pub` fields
    /// and a constructor jointly validating both ⇒ one candidate.
    #[test]
    fn public_invariant_bypass_struct_plus_combo_validating_constructor_produce_one_candidate() {
        let dir = TempDir::new("pattern-invariant-corroborated");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub struct Range {\n\
             \x20   pub low: u32,\n\
             \x20   pub high: u32,\n\
             }\n\
             impl Range {\n\
             \x20   pub fn new(low: u32, high: u32) -> Result<Self, String> {\n\
             \x20       if low >= high {\n\
             \x20           return Err(\"low must be less than high\".to_string());\n\
             \x20       }\n\
             \x20       Ok(Self { low, high })\n\
             \x20   }\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let candidates = analyze_workspace(&workspace, &[]);

        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        assert_eq!(candidate.pattern, RustPattern::SmartConstructor);
        assert_eq!(candidate.scope.krate, "fixture");
        assert_eq!(candidate.evidence.primary.locations.len(), 2);
        assert!(!candidate.evidence.independent.locations.is_empty());
        assert!(!candidate.contraindications.is_empty());
        assert!(candidate.migration.len() >= 2);
    }

    /// `public-invariant-bypass` (b): the same struct/constructor, but
    /// `#[non_exhaustive]` on the struct ⇒ no candidate, regardless of what
    /// the constructor validates.
    #[test]
    fn public_invariant_bypass_non_exhaustive_struct_produces_no_candidate() {
        let dir = TempDir::new("pattern-invariant-non-exhaustive");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "#[non_exhaustive]\n\
             pub struct Range {\n\
             \x20   pub low: u32,\n\
             \x20   pub high: u32,\n\
             }\n\
             impl Range {\n\
             \x20   pub fn new(low: u32, high: u32) -> Result<Self, String> {\n\
             \x20       if low >= high {\n\
             \x20           return Err(\"low must be less than high\".to_string());\n\
             \x20       }\n\
             \x20       Ok(Self { low, high })\n\
             \x20   }\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        assert!(analyze_workspace(&workspace, &[]).is_empty());
    }

    /// `public-invariant-bypass` (c): two `pub` fields, but the constructor
    /// only validates one field at a time (never a combination) ⇒ no
    /// candidate.
    #[test]
    fn public_invariant_bypass_single_field_validation_is_not_corroborated() {
        let dir = TempDir::new("pattern-invariant-single-field");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub struct Range {\n\
             \x20   pub low: u32,\n\
             \x20   pub high: u32,\n\
             }\n\
             impl Range {\n\
             \x20   pub fn new(low: u32, high: u32) -> Result<Self, String> {\n\
             \x20       if low > 1000 {\n\
             \x20           return Err(\"too big\".to_string());\n\
             \x20       }\n\
             \x20       Ok(Self { low, high })\n\
             \x20   }\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        assert!(analyze_workspace(&workspace, &[]).is_empty());
    }

    /// `manual-resource-lifecycle` (a): a function calling `register(...)`
    /// and `unregister(...)`, and the crate has no `impl Drop` anywhere ⇒
    /// one candidate.
    #[test]
    fn manual_resource_lifecycle_register_unregister_without_drop_produces_one_candidate() {
        let dir = TempDir::new("pattern-resource-corroborated");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub fn manage(handle: u32) {\n\
             \x20   register(handle);\n\
             \x20   unregister(handle);\n\
             }\n\
             fn register(_handle: u32) {}\n\
             fn unregister(_handle: u32) {}\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let candidates = analyze_workspace(&workspace, &[]);

        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        assert_eq!(candidate.pattern, RustPattern::RaiiGuard);
        assert_eq!(candidate.scope.krate, "fixture");
        assert!(!candidate.evidence.primary.locations.is_empty());
        assert_eq!(candidate.contraindications.len(), 3);
        assert!(candidate.migration.len() >= 2);
    }

    /// `manual-resource-lifecycle` (b): the same acquire/release pair, but
    /// the crate has an `impl Drop for X` elsewhere ⇒ no candidate (the
    /// independent signal is missing).
    #[test]
    fn manual_resource_lifecycle_with_an_existing_drop_impl_is_not_corroborated() {
        let dir = TempDir::new("pattern-resource-has-drop");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub fn manage(handle: u32) {\n\
             \x20   register(handle);\n\
             \x20   unregister(handle);\n\
             }\n\
             fn register(_handle: u32) {}\n\
             fn unregister(_handle: u32) {}\n\
             struct X;\n\
             impl Drop for X {\n\
             \x20   fn drop(&mut self) {}\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        assert!(analyze_workspace(&workspace, &[]).is_empty());
    }

    /// `manual-resource-lifecycle` (c): only `register(...)` without a
    /// matching `unregister(...)` ⇒ no candidate.
    #[test]
    fn manual_resource_lifecycle_without_a_matching_release_call_produces_no_candidate() {
        let dir = TempDir::new("pattern-resource-unmatched");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub fn manage(handle: u32) {\n\
             \x20   register(handle);\n\
             }\n\
             fn register(_handle: u32) {}\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        assert!(analyze_workspace(&workspace, &[]).is_empty());
    }
}
