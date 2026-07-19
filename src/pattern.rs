//! Pattern-candidate recommendations aggregated from projectwide evidence
//! (see todo.md §16 "Rust-Pattern-Empfehlungen aus projektweiter Evidenz").
//!
//! This is deliberately **not** the `Finding`/`Report`/verdict path: a
//! [`PatternCandidate`] is a heuristic design suggestion, never a gating
//! result. Nothing in this module is wired into `evidence_class_for_rule`,
//! the health score, or a baseline verdict (todo.md §16.1 "Pattern-
//! Empfehlungen sind keine normalen Findings").
//!
//! Scope of this module (first MVP slice, todo.md §16.6): only
//! [`PatternCandidate`]/[`CorroboratedEvidence`] and exactly one aggregation
//! rule, `stringly-error-boundary` (see [`analyze_workspace`]). The broader
//! `PrincipleHeuristic` type from todo.md §16.7 (abstract design-principle
//! heuristics like SRP/KISS/YAGNI) is a deliberately separate, later slice
//! and is not implemented here.

use std::collections::BTreeMap;
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
/// any superset of it). Currently just `stringly-error-boundary` — this is
/// the dispatch point future rules from todo.md §16.3 attach to.
pub fn analyze_workspace(workspace: &Workspace, findings: &[Finding]) -> Vec<PatternCandidate> {
    stringly_error_boundary_candidates(workspace, findings)
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
}
