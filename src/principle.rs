//! Design-principle heuristics (todo.md §16.7 "Designprinzipien: Evidenz
//! statt behaupteter Verletzung").
//!
//! Abstract design principles like Single Responsibility, Open/Closed, or
//! KISS are **never** emitted as a provable violation — judge only
//! operationalizes them into measurable signals and, at most, a cautious
//! [`PrincipleHeuristic`]. This is deliberately a **separate type** from
//! [`crate::pattern::PatternCandidate`] (todo.md §16.7: "`PatternCandidate`
//! und `PrincipleHeuristic` als getrennte Typen modellieren") even though
//! both reuse [`crate::pattern::CodeScope`], [`crate::pattern::Evidence`],
//! and [`crate::pattern::Contraindication`] — a pattern candidate recommends
//! a concrete Rust type/structure from corroborated symptoms, while a
//! principle heuristic interprets an abstract design property that always
//! depends on a non-observable purpose (todo.md §16.7: "die richtige
//! Architekturentscheidung hängt dennoch vom nicht beobachtbaren Zweck ab").
//!
//! Like [`crate::pattern::PatternCandidate`], nothing in this module is
//! wired into `evidence_class_for_rule`, the health score, or a baseline
//! verdict. [`PrincipleHeuristic`] has no confidence field at all (not even
//! one fixed to a single "heuristic" value) — the type itself guarantees
//! this assertion class can never be serialized as a fact, a bounded
//! semantic finding, or a CI-gating verdict (todo.md §16.7: "Der Typ selbst
//! garantiert, dass diese Aussage nie als Fakt, begrenzter semantischer
//! Befund oder CI-Verletzung serialisiert werden kann").
//!
//! Scope of this module (MVP slice): the [`PrincipleHeuristic`] type
//! infrastructure for the full §16.7 taxonomy ([`DesignPrinciple`] lists all
//! sixteen table entries), plus nine real detectors —
//! [`FunctionalCoreImperativeShell`](DesignPrinciple::FunctionalCoreImperativeShell)
//! (see [`functional_core_imperative_shell_candidates`]),
//! [`InterfaceSegregation`](DesignPrinciple::InterfaceSegregation) (see
//! [`interface_segregation_candidates`]),
//! [`DependencyInversion`](DesignPrinciple::DependencyInversion) (see
//! [`dependency_inversion_candidates`]),
//! [`Cohesion`](DesignPrinciple::Cohesion) (see [`cohesion_candidates`]),
//! [`LawOfDemeter`](DesignPrinciple::LawOfDemeter) (see
//! [`law_of_demeter_candidates`]),
//! [`BoundedResources`](DesignPrinciple::BoundedResources) (see
//! [`bounded_resources_candidates`]),
//! [`ParseDontValidate`](DesignPrinciple::ParseDontValidate) (see
//! [`parse_dont_validate_candidates`]),
//! [`ApiEvolvability`](DesignPrinciple::ApiEvolvability) (see
//! [`api_evolvability_candidates`]), and
//! [`UnsafeContainment`](DesignPrinciple::UnsafeContainment) (see
//! [`unsafe_containment_candidates`]). The remaining `DesignPrinciple`
//! variants are unused for now; they document the target space rather than
//! being implemented.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;
use syn::spanned::Spanned;
use syn::visit::Visit;

use crate::boundaries::{
    self, BoundaryConfig, BoundaryConfigError, MODULE_BOUNDARY_VIOLATION_RULE, ModuleBoundaryRule,
};
use crate::complexity::WorkspaceComplexity;
use crate::finding::{Finding, FindingId};
use crate::functions::walk_functions;
use crate::ingest::{CrateInfo, Workspace};
use crate::pattern::{CodeScope, Contraindication, Evidence, EvidenceLocation};
use crate::slop_text::{CommentSpan, extract_comments};

/// Cyclomatic-complexity threshold [`functional_core_imperative_shell_candidates`]
/// uses as "non-trivial branching" (signal 2). Chosen to mean more than a
/// couple of straight-line conditionals — contrast with `complexity-
/// inflation`'s much lower ≤3 threshold for a *newly introduced* function,
/// which is a different question (does this specific change add complexity)
/// from this heuristic's (does this function already combine I/O with
/// substantial branching).
pub const FUNCTIONAL_CORE_COMPLEXITY_THRESHOLD: u32 = 10;

/// Minimum method count [`interface_segregation_candidates`] treats as "a
/// large trait" (signal 1) — chosen to mean noticeably more than a small,
/// focused interface (contrast with a two- or three-method trait, which is
/// unremarkable on its own).
pub const INTERFACE_SEGREGATION_METHOD_THRESHOLD: usize = 5;

/// Minimum count of public top-level items (`pub fn`, `pub struct`, `pub
/// enum`, `pub trait`) [`cohesion_candidates`] treats as "several public
/// items in one file" (signal 1) — chosen to mean more than the one or two
/// items a small, single-purpose file typically declares.
pub const COHESION_ITEM_THRESHOLD: usize = 3;

/// Minimum number of chained method calls in one unbroken expression
/// [`law_of_demeter_candidates`] treats as "a long reach through an
/// intermediate object's own interface" (signal 1) — chosen to mean more
/// than a single extra hop (`a.b().c()`, two calls, is unremarkable) while
/// still being cheap to reach by adding one more call to an
/// already-two-call chain.
pub const LAW_OF_DEMETER_CHAIN_THRESHOLD: usize = 3;

/// Minimum field count [`api_evolvability_candidates`] treats as "an
/// evolvability concern" (signal 1) — chosen to mean more than a 0-1-field
/// struct, where adding a field isn't meaningfully different from the
/// struct's only field already being present; the concern this heuristic
/// targets is real once callers can already rely on a combination of
/// several fields at once.
pub const API_EVOLVABILITY_MIN_FIELDS: usize = 2;

/// A prüffähiges Designprinzip from todo.md §16.7's table. All sixteen table
/// entries are represented so the enum documents the full target space, even
/// though only [`Self::FunctionalCoreImperativeShell`] has a real detector in
/// this module today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesignPrinciple {
    Cohesion,
    OpenClosed,
    InterfaceSegregation,
    DependencyInversion,
    TellDontAsk,
    LawOfDemeter,
    Kiss,
    Yagni,
    FunctionalCoreImperativeShell,
    MakeIllegalStatesUnrepresentable,
    ParseDontValidate,
    Composition,
    ApiEvolvability,
    StructuredConcurrency,
    BoundedResources,
    UnsafeContainment,
}

impl DesignPrinciple {
    /// Stable kebab-case identifier, used both for [`PrincipleHeuristicId`]
    /// computation and TTY rendering.
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Cohesion => "cohesion",
            Self::OpenClosed => "open-closed",
            Self::InterfaceSegregation => "interface-segregation",
            Self::DependencyInversion => "dependency-inversion",
            Self::TellDontAsk => "tell-dont-ask",
            Self::LawOfDemeter => "law-of-demeter",
            Self::Kiss => "kiss",
            Self::Yagni => "yagni",
            Self::FunctionalCoreImperativeShell => "functional-core-imperative-shell",
            Self::MakeIllegalStatesUnrepresentable => "make-illegal-states-unrepresentable",
            Self::ParseDontValidate => "parse-dont-validate",
            Self::Composition => "composition",
            Self::ApiEvolvability => "api-evolvability",
            Self::StructuredConcurrency => "structured-concurrency",
            Self::BoundedResources => "bounded-resources",
            Self::UnsafeContainment => "unsafe-containment",
        }
    }
}

impl std::fmt::Display for DesignPrinciple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.slug())
    }
}

/// What additional information would make a [`PrincipleHeuristic`] more
/// decidable — mandatory on every heuristic (todo.md §16.7's output
/// contract: "`missing_evidence`: welche Information für eine belastbarere
/// Entscheidung fehlt").
#[derive(Debug, Clone, Serialize)]
pub struct MissingEvidence {
    pub description: String,
}

/// One possible structural response to a [`PrincipleHeuristic`], including
/// the "keep as-is" option every heuristic must offer (todo.md §16.7's
/// output contract: "`alternatives`: mindestens „beibehalten“ plus eine oder
/// mehrere mögliche Strukturänderungen").
#[derive(Debug, Clone, Serialize)]
pub struct DesignAlternative {
    pub description: String,
}

/// Stable identifier for a [`PrincipleHeuristic`], the same construction as
/// [`crate::pattern::PatternCandidateId`] (deterministic FNV-1a hash of
/// `(principle, normalized scope, sorted evidence identities)`) — see that
/// type's doc comment for why FNV-1a rather than blake3 or
/// `std::hash::DefaultHasher`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PrincipleHeuristicId(String);

impl PrincipleHeuristicId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn compute(
        principle: DesignPrinciple,
        scope: &CodeScope,
        evidence_identities: &[String],
    ) -> Self {
        let mut modules = scope.modules.clone();
        modules.sort();
        let mut identities = evidence_identities.to_vec();
        identities.sort();
        identities.dedup();
        let normalized = format!(
            "{}|{}|{}|{}",
            principle.slug(),
            scope.krate,
            modules.join(","),
            identities.join(",")
        );
        Self(format!(
            "principle:{}:{}",
            principle.slug(),
            fnv1a_hex(&normalized)
        ))
    }
}

impl std::fmt::Display for PrincipleHeuristicId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Deterministic, version-independent 64-bit FNV-1a hash, hex-encoded. Same
/// algorithm as `crate::pattern::fnv1a_hex`, duplicated rather than shared
/// because that function is private to `pattern.rs`.
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

/// A cautious interpretation of an abstract design principle, aggregated
/// from at least two independent evidence classes (todo.md §16.7: "Für jede
/// Principle-Heuristic mindestens zwei unabhängige Evidenzklassen verlangen
/// ... Reine Dateilänge oder Funktionsanzahl genügt nie").
///
/// Deliberately has **no confidence field**, not even one hardcoded to
/// `heuristic` — todo.md §16.7 requires the type itself, not a convention,
/// to guarantee this assertion class never becomes a fact, a bounded
/// semantic finding, or a CI-gating verdict. That guarantee holds
/// structurally: nothing in this crate attaches `PrincipleHeuristic` to
/// `Finding`/`Report`/`gate`/`baseline`/`health_score` — it is a fully
/// separate output, exactly like `PatternCandidate`.
#[derive(Debug, Clone, Serialize)]
pub struct PrincipleHeuristic {
    pub id: PrincipleHeuristicId,
    pub principle: DesignPrinciple,
    pub scope: CodeScope,
    pub evidence: Vec<Evidence>,
    pub interpretation: String,
    pub contraindications: Vec<Contraindication>,
    pub missing_evidence: Vec<MissingEvidence>,
    pub alternatives: Vec<DesignAlternative>,
    pub related_findings: Vec<FindingId>,
}

/// Runs every implemented principle-heuristic detector over `workspace`,
/// using `complexity` (the already-computed `judge::complexity::analyze_workspace`
/// result) as one of the independent evidence sources for
/// [`functional_core_imperative_shell_candidates`], and `boundary_config`
/// (the already-loaded `judge.toml` `[[boundary]]`/`[[module_boundary]]`
/// config, if any) as [`dependency_inversion_candidates`]' precondition —
/// that detector produces nothing when `boundary_config` is `None` or has no
/// `[[module_boundary]]` entries (todo.md §17: never guess project intent).
/// Merges results from [`interface_segregation_candidates`],
/// [`dependency_inversion_candidates`], and [`cohesion_candidates`] — this is
/// the dispatch point future detectors from todo.md §16.7's table attach to.
///
/// Returns [`BoundaryConfigError`] only via [`dependency_inversion_candidates`]
/// (an invalid `[[module_boundary]]`/`[[boundary]]` rule in `boundary_config`
/// is a config error, not a finding) — the same exit-2 treatment
/// `judge::boundaries::evaluate` gets everywhere else it's called.
pub fn analyze_workspace(
    workspace: &Workspace,
    complexity: &WorkspaceComplexity,
    boundary_config: Option<&BoundaryConfig>,
) -> Result<Vec<PrincipleHeuristic>, BoundaryConfigError> {
    let mut heuristics = functional_core_imperative_shell_candidates(workspace, complexity);
    heuristics.extend(interface_segregation_candidates(workspace));
    heuristics.extend(dependency_inversion_candidates(workspace, boundary_config)?);
    heuristics.extend(cohesion_candidates(workspace, complexity));
    heuristics.extend(law_of_demeter_candidates(workspace));
    heuristics.extend(bounded_resources_candidates(workspace));
    heuristics.extend(parse_dont_validate_candidates(workspace));
    heuristics.extend(api_evolvability_candidates(workspace));
    heuristics.extend(unsafe_containment_candidates(workspace));
    Ok(heuristics)
}

/// Functional Core, Imperative Shell (todo.md §16.7's table): "I/O,
/// Environment, Prozesssteuerung und umfangreiche deterministische
/// Berechnung in denselben Funktionen" → "Reinen Kern von der I/O-Shell
/// trennen".
///
/// Two independent signals, both required on the same function:
///
/// 1. **Structural (AST)** — the function body contains at least one call
///    shaped like an I/O/environment/process operation: either a call whose
///    path starts with `std::fs::`, `std::env::`, `std::process::`, or
///    `std::io::` ([`path_matches_io_prefix`]), or a method call whose name
///    is a common read/write method on such values (`read_to_string`,
///    `read_to_end`, `write_all`, `read_line`, `flush` —
///    [`IO_METHOD_NAMES`]). Matched purely by path/name, no type resolution
///    — the same accepted-limitation approach as `manual-resource-
///    lifecycle`'s acquire/release name matching in `pattern.rs`.
/// 2. **Measured (independent metric)** — the same function's cyclomatic
///    complexity, already computed by `judge::complexity::analyze_workspace`
///    and passed in as `complexity`, is at or above
///    [`FUNCTIONAL_CORE_COMPLEXITY_THRESHOLD`]. This is a structurally
///    different evidence source from signal 1: an independently computed
///    metric, not a second reading of the same AST pattern.
///
/// Only functions satisfying both produce a heuristic — exactly one per
/// function.
fn functional_core_imperative_shell_candidates(
    workspace: &Workspace,
    complexity: &WorkspaceComplexity,
) -> Vec<PrincipleHeuristic> {
    let cyclomatic_by_function = cyclomatic_by_function_map(complexity);

    let mut heuristics = Vec::new();
    for krate in &workspace.crates {
        for source in &krate.source_files {
            let Ok(text) = std::fs::read_to_string(&source.path) else {
                continue;
            };
            let Ok(ast) = syn::parse_file(&text) else {
                continue;
            };
            walk_functions(&ast, |site| {
                let Some(&cyclomatic) =
                    cyclomatic_by_function.get(&(source.path.clone(), site.qualified_name.clone()))
                else {
                    return;
                };
                if cyclomatic < FUNCTIONAL_CORE_COMPLEXITY_THRESHOLD {
                    return;
                }
                let io_hits = io_call_hits(site.block);
                if io_hits.is_empty() {
                    return;
                }
                heuristics.push(build_functional_core_imperative_shell_heuristic(
                    krate,
                    &source.path,
                    &site.qualified_name,
                    cyclomatic,
                    &io_hits,
                ));
            });
        }
    }
    heuristics
}

/// Builds `(file, qualified_name) -> cyclomatic complexity` from
/// `judge::complexity::analyze_workspace`'s per-function output — shared by
/// [`functional_core_imperative_shell_candidates`] (signal 2) and
/// [`cohesion_candidates`] (the `ComplexComputation` effect category), which
/// both need the same independently-computed metric.
fn cyclomatic_by_function_map(
    complexity: &WorkspaceComplexity,
) -> BTreeMap<(PathBuf, String), u32> {
    let mut map = BTreeMap::new();
    for info in &complexity.functions {
        map.insert(
            (info.file.clone(), info.qualified_name.clone()),
            info.cyclomatic,
        );
    }
    map
}

const IO_PATH_PREFIX_PAIRS: &[(&str, &str)] = &[
    ("std", "fs"),
    ("std", "env"),
    ("std", "process"),
    ("std", "io"),
];

const IO_METHOD_NAMES: &[&str] = &[
    "read_to_string",
    "read_to_end",
    "write_all",
    "read_line",
    "flush",
];

/// Whether `path` contains the consecutive segment pair `std::fs`,
/// `std::env`, `std::process`, or `std::io` anywhere (see
/// [`functional_core_imperative_shell_candidates`]'s signal 1).
fn path_matches_io_prefix(path: &syn::Path) -> bool {
    let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
    segments.windows(2).any(|pair| {
        IO_PATH_PREFIX_PAIRS
            .iter()
            .any(|(a, b)| pair[0] == *a && pair[1] == *b)
    })
}

/// Rendered source text of every call in `block` matching
/// [`functional_core_imperative_shell_candidates`]'s signal 1 (I/O-path call
/// or I/O-shaped method call).
fn io_call_hits(block: &syn::Block) -> Vec<String> {
    use quote::ToTokens;

    struct Finder {
        hits: Vec<String>,
    }
    impl<'ast> Visit<'ast> for Finder {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let syn::Expr::Path(expr_path) = node.func.as_ref()
                && path_matches_io_prefix(&expr_path.path)
            {
                self.hits.push(node.func.to_token_stream().to_string());
            }
            syn::visit::visit_expr_call(self, node);
        }

        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            let name = node.method.to_string();
            if IO_METHOD_NAMES.contains(&name.as_str()) {
                self.hits.push(format!(".{name}(...)"));
            }
            syn::visit::visit_expr_method_call(self, node);
        }
    }
    let mut finder = Finder { hits: Vec::new() };
    finder.visit_block(block);
    finder.hits
}

fn build_functional_core_imperative_shell_heuristic(
    krate: &CrateInfo,
    file: &Path,
    item_path: &str,
    cyclomatic: u32,
    io_hits: &[String],
) -> PrincipleHeuristic {
    let scope = CodeScope {
        krate: krate.name.clone(),
        modules: vec![item_path.to_string()],
    };
    let location = EvidenceLocation {
        file: file.to_path_buf(),
        item_path: Some(item_path.to_string()),
    };

    let structural = Evidence {
        description: format!(
            "`{item_path}` calls at least one I/O-/environment-/process-shaped operation: {}.",
            io_hits.join(", ")
        ),
        locations: vec![location.clone()],
    };
    let measured = Evidence {
        description: format!(
            "`{item_path}` has a cyclomatic complexity of {cyclomatic}, at or above the \
             {FUNCTIONAL_CORE_COMPLEXITY_THRESHOLD} threshold this heuristic treats as \
             non-trivial branching — an independently computed metric from \
             `judge::complexity`, not a second reading of the I/O call pattern above."
        ),
        locations: vec![location],
    };

    let evidence_identities = vec![item_path.to_string()];
    let id = PrincipleHeuristicId::compute(
        DesignPrinciple::FunctionalCoreImperativeShell,
        &scope,
        &evidence_identities,
    );

    PrincipleHeuristic {
        id,
        principle: DesignPrinciple::FunctionalCoreImperativeShell,
        scope,
        evidence: vec![structural, measured],
        interpretation: "This function combines I/O/environment/process operations with \
            non-trivial branching complexity in one place. Separating the deterministic \
            computation from the I/O shell could make the computation independently testable."
            .to_string(),
        contraindications: vec![
            Contraindication {
                description: "A thin orchestration function that mostly sequences I/O calls \
                    with light glue logic may not benefit from further splitting."
                    .to_string(),
            },
            Contraindication {
                description: "If the branching complexity comes from error handling around the \
                    I/O itself (not separate business logic), separating core from shell may \
                    not apply."
                    .to_string(),
            },
        ],
        missing_evidence: vec![MissingEvidence {
            description: "Whether the branching logic is genuinely independent business logic \
                (vs. I/O-specific error handling) is not distinguished by this heuristic."
                .to_string(),
        }],
        alternatives: vec![
            DesignAlternative {
                description: "Keep the function as-is.".to_string(),
            },
            DesignAlternative {
                description: "Extract the non-I/O computation into a pure, \
                    independently-testable function; keep I/O calls in a thin wrapper."
                    .to_string(),
            },
        ],
        related_findings: Vec::new(),
    }
}

/// A trait declaration found while scanning a crate for
/// [`interface_segregation_candidates`]: its name, its method count (signal
/// 1), and where it lives.
struct TraitDeclaration {
    name: String,
    method_count: usize,
    location: EvidenceLocation,
}

/// An `impl TraitName for Type` block found while scanning a crate for
/// [`interface_segregation_candidates`]: which trait it implements (matched
/// by name only — see that function's doc comment), the `Self` type, the
/// set of methods the block itself defines (not inherited defaults —
/// signal 2), and where it lives.
struct TraitImplementation {
    trait_name: String,
    self_type: String,
    overridden_methods: std::collections::BTreeSet<String>,
    location: EvidenceLocation,
}

/// Interface Segregation (todo.md §16.7's table): "großes Trait, Nutzer
/// verwenden stabile disjunkte Methodengruppen" → "Trait könnte mehrere
/// Consumer-Interfaces enthalten".
///
/// Two independent signals, both required on the same trait:
///
/// 1. **Structural (AST)** — the trait declares at least
///    [`INTERFACE_SEGREGATION_METHOD_THRESHOLD`] methods (`syn::TraitItemFn`
///    entries, counted whether or not they carry a default body).
/// 2. **Empirical usage pattern (independent signal)** — within the same
///    crate, at least two `impl TraitName for Type` blocks exist whose
///    *overridden* method sets (the methods the impl block itself defines,
///    not inherited defaults) are non-empty and pairwise disjoint — no
///    method name shared between the two. This is structurally different
///    from signal 1: it is empirical evidence that implementors cluster
///    into non-overlapping capability groups, not another reading of trait
///    size.
///
/// Traits are matched to their impls purely by trait name (last path
/// segment), not full path resolution — the same accepted-limitation
/// approach as [`path_matches_io_prefix`] uses for I/O calls. At most one
/// heuristic per trait: the first disjoint impl pair found, in
/// deterministic (`self_type`, file) order.
fn interface_segregation_candidates(workspace: &Workspace) -> Vec<PrincipleHeuristic> {
    use quote::ToTokens;

    struct Collector {
        file: PathBuf,
        traits: Vec<TraitDeclaration>,
        impls: Vec<TraitImplementation>,
    }
    impl<'ast> Visit<'ast> for Collector {
        fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
            let method_count = node
                .items
                .iter()
                .filter(|item| matches!(item, syn::TraitItem::Fn(_)))
                .count();
            self.traits.push(TraitDeclaration {
                name: node.ident.to_string(),
                method_count,
                location: EvidenceLocation {
                    file: self.file.clone(),
                    item_path: Some(node.ident.to_string()),
                },
            });
            syn::visit::visit_item_trait(self, node);
        }

        fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
            if let Some((_, path, _)) = &node.trait_
                && let Some(segment) = path.segments.last()
            {
                let trait_name = segment.ident.to_string();
                let self_type = node.self_ty.to_token_stream().to_string();
                let overridden_methods = node
                    .items
                    .iter()
                    .filter_map(|item| match item {
                        syn::ImplItem::Fn(method) => Some(method.sig.ident.to_string()),
                        _ => None,
                    })
                    .collect();
                self.impls.push(TraitImplementation {
                    trait_name: trait_name.clone(),
                    location: EvidenceLocation {
                        file: self.file.clone(),
                        item_path: Some(format!("<{self_type} as {trait_name}>")),
                    },
                    self_type,
                    overridden_methods,
                });
            }
            syn::visit::visit_item_impl(self, node);
        }
    }

    let mut heuristics = Vec::new();
    for krate in &workspace.crates {
        let mut traits = Vec::new();
        let mut impls = Vec::new();
        for source in &krate.source_files {
            let Ok(text) = std::fs::read_to_string(&source.path) else {
                continue;
            };
            let Ok(ast) = syn::parse_file(&text) else {
                continue;
            };
            let mut collector = Collector {
                file: source.path.clone(),
                traits: Vec::new(),
                impls: Vec::new(),
            };
            collector.visit_file(&ast);
            traits.extend(collector.traits);
            impls.extend(collector.impls);
        }

        for trait_decl in &traits {
            if trait_decl.method_count < INTERFACE_SEGREGATION_METHOD_THRESHOLD {
                continue;
            }
            let mut candidates: Vec<&TraitImplementation> = impls
                .iter()
                .filter(|imp| {
                    imp.trait_name == trait_decl.name && !imp.overridden_methods.is_empty()
                })
                .collect();
            candidates.sort_by(|a, b| {
                (&a.self_type, &a.location.file).cmp(&(&b.self_type, &b.location.file))
            });

            let disjoint_pair = candidates.iter().enumerate().find_map(|(i, first)| {
                candidates[i + 1..]
                    .iter()
                    .find(|second| {
                        first
                            .overridden_methods
                            .is_disjoint(&second.overridden_methods)
                    })
                    .map(|second| (*first, *second))
            });

            if let Some((first, second)) = disjoint_pair {
                heuristics.push(build_interface_segregation_heuristic(
                    krate, trait_decl, first, second,
                ));
            }
        }
    }
    heuristics
}

fn build_interface_segregation_heuristic(
    krate: &CrateInfo,
    trait_decl: &TraitDeclaration,
    first: &TraitImplementation,
    second: &TraitImplementation,
) -> PrincipleHeuristic {
    let scope = CodeScope {
        krate: krate.name.clone(),
        modules: vec![trait_decl.name.clone()],
    };

    let structural = Evidence {
        description: format!(
            "`{}` declares {} methods, at or above the {INTERFACE_SEGREGATION_METHOD_THRESHOLD} \
             threshold this heuristic treats as a large trait.",
            trait_decl.name, trait_decl.method_count
        ),
        locations: vec![trait_decl.location.clone()],
    };
    let usage = Evidence {
        description: format!(
            "In this crate, `{}` overrides {{{}}} and `{}` overrides {{{}}} of `{}` — two \
             implementors whose overridden method sets share no method name.",
            first.self_type,
            sorted_joined(&first.overridden_methods),
            second.self_type,
            sorted_joined(&second.overridden_methods),
            trait_decl.name
        ),
        locations: vec![first.location.clone(), second.location.clone()],
    };

    let evidence_identities = vec![
        trait_decl.name.clone(),
        first.self_type.clone(),
        second.self_type.clone(),
    ];
    let id = PrincipleHeuristicId::compute(
        DesignPrinciple::InterfaceSegregation,
        &scope,
        &evidence_identities,
    );

    PrincipleHeuristic {
        id,
        principle: DesignPrinciple::InterfaceSegregation,
        scope,
        evidence: vec![structural, usage],
        interpretation: format!(
            "This trait has {} methods, and its implementors in this crate split into \
             non-overlapping groups by which methods they override. That may indicate the \
             trait actually models more than one consumer-facing interface.",
            trait_decl.method_count
        ),
        contraindications: vec![
            Contraindication {
                description: "A trait with many default-implemented convenience methods on top \
                    of a small required core is a common, intentional design — not \
                    automatically evidence of multiple interfaces."
                    .to_string(),
            },
            Contraindication {
                description: "Only 2 implementors may be too few to establish a real usage \
                    pattern, rather than incidental non-overlap."
                    .to_string(),
            },
        ],
        missing_evidence: vec![MissingEvidence {
            description: "Whether callers actually depend on the trait through the full \
                interface or only through one of the observed subsets is not checked here \
                (would need cross-crate consumer analysis)."
                .to_string(),
        }],
        alternatives: vec![
            DesignAlternative {
                description: "Keep the trait as-is.".to_string(),
            },
            DesignAlternative {
                description: "Split into two or more smaller traits along the observed method \
                    groups, potentially with a supertrait for shared methods if any exist."
                    .to_string(),
            },
        ],
        related_findings: Vec::new(),
    }
}

/// Deterministic, comma-joined rendering of a method-name set for evidence
/// text (sorted so the same set always renders identically).
fn sorted_joined(methods: &std::collections::BTreeSet<String>) -> String {
    methods.iter().cloned().collect::<Vec<_>>().join(", ")
}

/// Derives a source file's module path purely from its position under
/// `crate_root/src/` — identical directory-convention logic to
/// `crate::boundaries::module_path_for_file`, duplicated rather than shared
/// because that function is private to `boundaries.rs` (same trade-off as
/// this module's own `fnv1a_hex`, duplicated from `pattern.rs` for the same
/// reason). See that function's doc comment for the exact convention.
fn module_path_for_file(crate_root: &Path, file_path: &Path) -> Option<String> {
    let relative = file_path.strip_prefix(crate_root).ok()?;
    let mut components: Vec<String> = relative
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(name) => Some(name.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    if components.first().map(String::as_str) != Some("src") {
        return None;
    }
    components.remove(0);
    if components.is_empty() {
        return None;
    }
    if components.len() == 1 && matches!(components[0].as_str(), "lib.rs" | "main.rs") {
        return Some(String::new());
    }
    if components.first().map(String::as_str) == Some("bin") {
        return Some(String::new());
    }

    let last = components.last().cloned()?;
    if last == "mod.rs" {
        components.pop();
    } else if let Some(stem) = last.strip_suffix(".rs") {
        let stem = stem.to_string();
        *components.last_mut().expect("just checked non-empty") = stem;
    } else {
        return None;
    }
    Some(components.join("::"))
}

/// Whether `module_path` is `prefix` itself, or a descendant of it — a
/// `::`-segment prefix match, not a raw string prefix match. Identical logic
/// to `crate::boundaries::module_path_under`, duplicated for the same reason
/// as [`module_path_for_file`].
fn module_path_under(module_path: &str, prefix: &str) -> bool {
    module_path == prefix || module_path.starts_with(&format!("{prefix}::"))
}

/// One `pub fn` (free function or impl method) whose parameter or return
/// type's path textually begins with `crate::<forbidden>` — signal 2 for
/// [`dependency_inversion_candidates`].
struct LeakedSignature {
    item_path: String,
    leaked_type: String,
    forbidden: String,
    location: EvidenceLocation,
}

/// Whether `ty` (after unwrapping a `&`/`&mut` reference) is a path type
/// whose segments are `crate::<one of `forbidden`>::...` — pure
/// `syn::Path`-segment prefix matching, no type resolution, mirroring
/// `boundaries::segments_match_forbidden`'s own accepted-limitation approach
/// but restricted to signature types. Returns the rendered type text and the
/// matched `forbidden` entry on a hit.
fn leaked_type_in(ty: &syn::Type, forbidden: &[String]) -> Option<(String, String)> {
    use quote::ToTokens;

    let inner = match ty {
        syn::Type::Reference(reference) => reference.elem.as_ref(),
        other => other,
    };
    let syn::Type::Path(type_path) = inner else {
        return None;
    };
    let segments: Vec<String> = type_path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    if segments.first().map(String::as_str) != Some("crate") {
        return None;
    }
    let rest = &segments[1..];
    forbidden.iter().find_map(|target| {
        let target_segments: Vec<&str> = target.split("::").collect();
        let is_match = rest.len() >= target_segments.len()
            && rest
                .iter()
                .zip(target_segments.iter())
                .all(|(segment, target_segment)| segment == target_segment);
        is_match.then(|| (ty.to_token_stream().to_string(), target.clone()))
    })
}

/// Checks one `pub fn`/`pub` impl-method signature against [`leaked_type_in`],
/// pushing a [`LeakedSignature`] onto `hits` for every parameter/return type
/// that matches.
fn check_signature(
    hits: &mut Vec<LeakedSignature>,
    item_path: &str,
    sig: &syn::Signature,
    file: &Path,
    forbidden: &[String],
) {
    let mut types: Vec<&syn::Type> = sig
        .inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Typed(pat_type) => Some(pat_type.ty.as_ref()),
            syn::FnArg::Receiver(_) => None,
        })
        .collect();
    if let syn::ReturnType::Type(_, ty) = &sig.output {
        types.push(ty.as_ref());
    }
    for ty in types {
        if let Some((leaked_type, forbidden)) = leaked_type_in(ty, forbidden) {
            hits.push(LeakedSignature {
                item_path: item_path.to_string(),
                leaked_type,
                forbidden,
                location: EvidenceLocation {
                    file: file.to_path_buf(),
                    item_path: Some(item_path.to_string()),
                },
            });
        }
    }
}

/// Every [`LeakedSignature`] found in `krate`'s source files whose derived
/// module path (see [`module_path_for_file`]) falls under `from_module` —
/// the same file-scoping [`dependency_inversion_candidates`]' signal 1 uses
/// via `boundaries::evaluate_module_boundary_rule` (private to that module,
/// so scoped independently here with the duplicated helpers above). Files
/// that fail to read or parse are silently skipped, the same accepted
/// limitation `boundaries.rs` documents for its own scan.
fn leaked_signatures(
    krate: &CrateInfo,
    from_module: &str,
    forbidden: &[String],
) -> Vec<LeakedSignature> {
    let mut leaks = Vec::new();
    for source in &krate.source_files {
        let Some(module_path) = module_path_for_file(&krate.root, &source.path) else {
            continue;
        };
        if !module_path_under(&module_path, from_module) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&source.path) else {
            continue;
        };
        let Ok(ast) = syn::parse_file(&text) else {
            continue;
        };
        walk_functions(&ast, |site| {
            if !matches!(site.vis, Some(syn::Visibility::Public(_))) {
                return;
            }
            check_signature(
                &mut leaks,
                &site.qualified_name,
                site.sig,
                &source.path,
                forbidden,
            );
        });
    }
    leaks
}

/// Dependency Inversion (todo.md §16.7's table): "konfigurierte Domain-
/// Schicht hängt direkt von konkreter Infrastruktur ab; Infrastrukturtypen
/// leaken in öffentliche Domain-Signaturen" → "Port-/Adapter-Grenze prüfen".
///
/// Requires a user-configured `[[module_boundary]]` in `judge.toml`
/// (`boundary_config`) — todo.md §17 forbids guessing project intent, so
/// without a configured `from`/`forbidden` module pairing this detector
/// produces nothing: not "no violation found", but "not applicable". When
/// `boundary_config` is `None`, or has no `[[module_boundary]]` entries,
/// this returns an empty `Vec` without doing any further work.
///
/// Two independent signals, both required for the same configured
/// `[[module_boundary]]` rule:
///
/// 1. **Corroborating finding (call-level, already computed elsewhere)** —
///    [`boundaries::evaluate`] reports at least one `module-boundary-
///    violation` finding for this rule (matched by `rule.name`, since a
///    finding's `item_path` is rendered as `"{rule.name} [direct]: ..."` —
///    see `boundaries::module_boundary_finding`). This shows the crate
///    already crosses this boundary somewhere at the reference level.
/// 2. **API-signature leak (independent, `pub fn` signature level)** — at
///    least one `pub fn` in a file under the rule's `from` module has a
///    parameter or return type whose path textually begins with
///    `crate::<forbidden>` for one of the rule's `forbidden` targets (see
///    [`leaked_signatures`]). Qualitatively different from signal 1: a
///    call-level finding says the module *references* forbidden code
///    somewhere; this says a forbidden type is *exposed in the public API*
///    of the domain-tagged module.
///
/// Only rules satisfying both produce a heuristic — at most one per
/// `[[module_boundary]]` rule, with `related_findings` pointing at the
/// `module-boundary-violation` finding ids from signal 1.
fn dependency_inversion_candidates(
    workspace: &Workspace,
    boundary_config: Option<&BoundaryConfig>,
) -> Result<Vec<PrincipleHeuristic>, BoundaryConfigError> {
    let Some(config) = boundary_config else {
        return Ok(Vec::new());
    };
    if config.module_boundaries.is_empty() {
        return Ok(Vec::new());
    }

    let boundaries = boundaries::evaluate(workspace, config)?;

    let mut heuristics = Vec::new();
    for rule in &config.module_boundaries {
        let Some(krate) = workspace.crates.iter().find(|k| k.name == rule.krate) else {
            continue;
        };

        let prefix = format!("{} [direct]:", rule.name);
        let related_findings: Vec<&Finding> = boundaries
            .findings
            .iter()
            .filter(|finding| {
                finding.rule == MODULE_BOUNDARY_VIOLATION_RULE
                    && finding.location.item_path.starts_with(&prefix)
            })
            .collect();
        if related_findings.is_empty() {
            continue;
        }

        let leaks = leaked_signatures(krate, &rule.from, &rule.forbidden);
        if leaks.is_empty() {
            continue;
        }

        heuristics.push(build_dependency_inversion_heuristic(
            krate,
            rule,
            &related_findings,
            &leaks,
        ));
    }
    Ok(heuristics)
}

fn build_dependency_inversion_heuristic(
    krate: &CrateInfo,
    rule: &ModuleBoundaryRule,
    related_findings: &[&Finding],
    leaks: &[LeakedSignature],
) -> PrincipleHeuristic {
    let scope = CodeScope {
        krate: krate.name.clone(),
        modules: vec![rule.from.clone()],
    };

    let call_level = Evidence {
        description: format!(
            "`{}` already has {} `module-boundary-violation` finding(s) for `{}` -> {{{}}}, \
             recorded independently by `judge::boundaries::evaluate`.",
            rule.name,
            related_findings.len(),
            rule.from,
            rule.forbidden.join(", "),
        ),
        locations: related_findings
            .iter()
            .map(|finding| EvidenceLocation {
                file: finding.location.file.clone(),
                item_path: Some(finding.location.item_path.clone()),
            })
            .collect(),
    };

    let leak_descriptions: Vec<String> = leaks
        .iter()
        .map(|leak| {
            format!(
                "`{}` in `{}` names `{}` (matches forbidden module `{}`)",
                leak.item_path, rule.from, leak.leaked_type, leak.forbidden
            )
        })
        .collect();
    let signature_leak = Evidence {
        description: format!(
            "In `{}`, {} public function signature(s) name a type whose path begins with \
             `crate::<forbidden module>`: {}.",
            rule.from,
            leaks.len(),
            leak_descriptions.join("; "),
        ),
        locations: leaks.iter().map(|leak| leak.location.clone()).collect(),
    };

    let mut evidence_identities = vec![rule.name.clone()];
    evidence_identities.extend(leaks.iter().map(|leak| leak.item_path.clone()));
    evidence_identities.extend(related_findings.iter().map(|f| f.id.as_str().to_string()));
    let id = PrincipleHeuristicId::compute(
        DesignPrinciple::DependencyInversion,
        &scope,
        &evidence_identities,
    );

    PrincipleHeuristic {
        id,
        principle: DesignPrinciple::DependencyInversion,
        scope,
        evidence: vec![call_level, signature_leak],
        interpretation: "This module boundary is both crossed at the call level and has \
            infrastructure types leaking into public signatures of the domain-tagged module. \
            Introducing a port/trait at the boundary could decouple the domain module from the \
            concrete infrastructure type."
            .to_string(),
        contraindications: vec![
            Contraindication {
                description: "A small, stable, unlikely-to-change infrastructure type (e.g. a \
                    newtype wrapper) may not justify the indirection of a port/trait."
                    .to_string(),
            },
            Contraindication {
                description: "If the module boundary itself is new/experimental configuration, \
                    the violations may reflect an intentional transition period rather than a \
                    design flaw."
                    .to_string(),
            },
        ],
        missing_evidence: vec![MissingEvidence {
            description: "Whether the leaked type is actually varied/swapped in practice (the \
                core justification for dependency inversion) is not checked — only that a \
                public signature names it."
                .to_string(),
        }],
        alternatives: vec![
            DesignAlternative {
                description: "Keep the module boundary as-is.".to_string(),
            },
            DesignAlternative {
                description: "Introduce a trait/port owned by the domain module, implement it \
                    for the infrastructure type, and change the public signature to use the \
                    trait object/generic instead."
                    .to_string(),
            },
        ],
        related_findings: related_findings.iter().map(|f| f.id.clone()).collect(),
    }
}

/// One of the three effect categories [`cohesion_candidates`]'s signal 2
/// checks for independently on each public item — see that function's doc
/// comment for the detection rule per category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EffectCategory {
    IoOperations,
    TerminalOutput,
    ComplexComputation,
}

impl EffectCategory {
    fn label(self) -> &'static str {
        match self {
            Self::IoOperations => "I/O operations",
            Self::TerminalOutput => "terminal output",
            Self::ComplexComputation => "complex computation",
        }
    }
}

const TERMINAL_OUTPUT_MACROS: &[&str] = &["println", "eprintln", "print", "eprint"];
const WRITE_MACROS: &[&str] = &["write", "writeln"];
const TERMINAL_STREAM_MARKERS: &[&str] = &["stdout", "stderr", "Stdout", "Stderr"];

/// Rendered source text of every macro call in `block` matching
/// [`cohesion_candidates`]'s `TerminalOutput` category: `println!`/
/// `eprintln!`/`print!`/`eprint!`, or `write!`/`writeln!` on an expression
/// whose token stream textually contains `stdout`/`stderr`/`Stdout`/
/// `Stderr`. Matched via `visit_macro` (not `visit_expr_macro`), the same
/// approach `slop.rs` uses, so this also sees macro invocations used as
/// statements, not just as expressions.
fn terminal_output_hits(block: &syn::Block) -> Vec<String> {
    struct Finder {
        hits: Vec<String>,
    }
    impl<'ast> Visit<'ast> for Finder {
        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            if let Some(name) = node.path.get_ident().map(ToString::to_string) {
                let is_terminal_output = TERMINAL_OUTPUT_MACROS.contains(&name.as_str())
                    || (WRITE_MACROS.contains(&name.as_str())
                        && TERMINAL_STREAM_MARKERS
                            .iter()
                            .any(|marker| node.tokens.to_string().contains(marker)));
                if is_terminal_output {
                    self.hits.push(format!("{name}!(...)"));
                }
            }
            syn::visit::visit_macro(self, node);
        }
    }
    let mut finder = Finder { hits: Vec::new() };
    finder.visit_block(block);
    finder.hits
}

/// One effect category a [`FileItem`] shows, plus a short rendering of the
/// concrete evidence for it (the I/O call, the output macro, or the
/// cyclomatic complexity value).
struct CategoryHit {
    category: EffectCategory,
    detail: String,
}

/// One public top-level item counted toward [`cohesion_candidates`]'s signal
/// 1 (`pub fn`/impl method, `pub struct`, `pub enum`, `pub trait`), together
/// with whichever [`EffectCategory`] hits signal 2 found on it — empty for
/// `struct`/`enum`/`trait` declarations, which have no body to check.
struct FileItem {
    name: String,
    location: EvidenceLocation,
    categories: Vec<CategoryHit>,
}

/// Collects public top-level `struct`/`enum`/`trait` declarations in one
/// parsed file — part of [`cohesion_candidates`]'s signal-1 item count.
/// Public `fn`/impl-method items are collected separately via
/// [`walk_functions`] in [`collect_file_items`], since that helper already
/// tracks their impl `Self`-type-qualified names and bodies (needed for
/// signal 2).
struct DeclaredItemCollector {
    file: PathBuf,
    items: Vec<FileItem>,
}

impl DeclaredItemCollector {
    fn push(&mut self, name: String) {
        self.items.push(FileItem {
            location: EvidenceLocation {
                file: self.file.clone(),
                item_path: Some(name.clone()),
            },
            name,
            categories: Vec::new(),
        });
    }
}

impl<'ast> Visit<'ast> for DeclaredItemCollector {
    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        if matches!(node.vis, syn::Visibility::Public(_)) {
            self.push(node.ident.to_string());
        }
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        if matches!(node.vis, syn::Visibility::Public(_)) {
            self.push(node.ident.to_string());
        }
        syn::visit::visit_item_enum(self, node);
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        if matches!(node.vis, syn::Visibility::Public(_)) {
            self.push(node.ident.to_string());
        }
        syn::visit::visit_item_trait(self, node);
    }
}

/// Every public top-level item in one parsed file, in source order: `pub
/// fn`s and `pub` impl methods first (via [`walk_functions`], each carrying
/// whichever [`EffectCategory`] hits [`cohesion_candidates`]'s signal 2
/// found in its body), followed by `pub struct`/`pub enum`/`pub trait`
/// declarations (via [`DeclaredItemCollector`], which never carry a
/// category — they have no body to check).
fn collect_file_items(
    ast: &syn::File,
    file: &Path,
    cyclomatic_by_function: &BTreeMap<(PathBuf, String), u32>,
) -> Vec<FileItem> {
    let mut items = Vec::new();

    walk_functions(ast, |site| {
        let Some(vis) = site.vis else {
            return;
        };
        if !matches!(vis, syn::Visibility::Public(_)) {
            return;
        }

        let mut categories = Vec::new();
        let io_hits = io_call_hits(site.block);
        if !io_hits.is_empty() {
            categories.push(CategoryHit {
                category: EffectCategory::IoOperations,
                detail: io_hits.join(", "),
            });
        }
        let output_hits = terminal_output_hits(site.block);
        if !output_hits.is_empty() {
            categories.push(CategoryHit {
                category: EffectCategory::TerminalOutput,
                detail: output_hits.join(", "),
            });
        }
        if let Some(&cyclomatic) =
            cyclomatic_by_function.get(&(file.to_path_buf(), site.qualified_name.clone()))
            && cyclomatic >= FUNCTIONAL_CORE_COMPLEXITY_THRESHOLD
        {
            categories.push(CategoryHit {
                category: EffectCategory::ComplexComputation,
                detail: format!("cyclomatic complexity {cyclomatic}"),
            });
        }

        items.push(FileItem {
            location: EvidenceLocation {
                file: file.to_path_buf(),
                item_path: Some(site.qualified_name.clone()),
            },
            name: site.qualified_name,
            categories,
        });
    });

    let mut declared = DeclaredItemCollector {
        file: file.to_path_buf(),
        items: Vec::new(),
    };
    declared.visit_file(ast);
    items.extend(declared.items);

    items
}

/// The first pair of distinct items in `items` (in list order) that each
/// show at least one [`EffectCategory`], where those categories differ — see
/// [`cohesion_candidates`]'s signal 2. An item showing more than one
/// category on its own does not count against itself; only a category held
/// by one item and a *different* category held by a *different* item
/// qualifies (functional-core-imperative-shell's domain is a single item
/// mixing categories, not this).
fn first_differing_category_pair(items: &[FileItem]) -> Option<(usize, usize)> {
    for i in 0..items.len() {
        for j in (i + 1)..items.len() {
            let differs = items[i].categories.iter().any(|hit_i| {
                items[j]
                    .categories
                    .iter()
                    .any(|hit_j| hit_i.category != hit_j.category)
            });
            if differs {
                return Some((i, j));
            }
        }
    }
    None
}

/// Single Responsibility / Cohesion (todo.md §16.7's table): "getrennte
/// Call-/Dependency-/Change-Cluster, gemischte Effektarten, kaum interne
/// Interaktion" → "Möglicher Kohäsionsmangel; Split prüfen".
///
/// Two independent signals, both required for the same file:
///
/// 1. **Structural (item count)** — the file declares at least
///    [`COHESION_ITEM_THRESHOLD`] public top-level items: `pub fn`s and
///    `pub` impl methods (via [`walk_functions`]), plus `pub struct`/`pub
///    enum`/`pub trait` declarations.
/// 2. **Categorical diversity (independent of item count)** — at least two
///    *different* items in the file each show a *different*
///    [`EffectCategory`]: `IoOperations` (reusing
///    [`functional_core_imperative_shell_candidates`]'s I/O-call detection,
///    [`io_call_hits`]), `TerminalOutput` ([`terminal_output_hits`]), or
///    `ComplexComputation` (the same cyclomatic-complexity threshold as
///    `functional-core-imperative-shell`,
///    [`FUNCTIONAL_CORE_COMPLEXITY_THRESHOLD`], via `complexity`). One item
///    mixing several categories itself does not satisfy this signal — that
///    is `functional-core-imperative-shell`'s domain, not this one's; see
///    [`first_differing_category_pair`].
///
/// Only files satisfying both produce a heuristic — exactly one per file.
fn cohesion_candidates(
    workspace: &Workspace,
    complexity: &WorkspaceComplexity,
) -> Vec<PrincipleHeuristic> {
    let cyclomatic_by_function = cyclomatic_by_function_map(complexity);

    let mut heuristics = Vec::new();
    for krate in &workspace.crates {
        for source in &krate.source_files {
            let Ok(text) = std::fs::read_to_string(&source.path) else {
                continue;
            };
            let Ok(ast) = syn::parse_file(&text) else {
                continue;
            };

            let items = collect_file_items(&ast, &source.path, &cyclomatic_by_function);
            if items.len() < COHESION_ITEM_THRESHOLD {
                continue;
            }
            if first_differing_category_pair(&items).is_some() {
                heuristics.push(build_cohesion_heuristic(krate, &source.path, &items));
            }
        }
    }
    heuristics
}

fn build_cohesion_heuristic(
    krate: &CrateInfo,
    file: &Path,
    items: &[FileItem],
) -> PrincipleHeuristic {
    let module =
        module_path_for_file(&krate.root, file).unwrap_or_else(|| file.display().to_string());
    let scope = CodeScope {
        krate: krate.name.clone(),
        modules: vec![module],
    };

    let item_names: Vec<&str> = items.iter().map(|item| item.name.as_str()).collect();
    let structural = Evidence {
        description: format!(
            "This file declares {} public top-level items, at or above the \
             {COHESION_ITEM_THRESHOLD} threshold this heuristic treats as several public items \
             in one file: {}.",
            items.len(),
            item_names.join(", "),
        ),
        locations: items.iter().map(|item| item.location.clone()).collect(),
    };

    let categorized: Vec<&FileItem> = items
        .iter()
        .filter(|item| !item.categories.is_empty())
        .collect();
    let category_descriptions: Vec<String> = categorized
        .iter()
        .map(|item| {
            let hits: Vec<String> = item
                .categories
                .iter()
                .map(|hit| format!("{} ({})", hit.category.label(), hit.detail))
                .collect();
            format!("`{}` shows {}", item.name, hits.join(" and "))
        })
        .collect();
    let category_evidence = Evidence {
        description: format!(
            "At least two of these items show a different effect category from each other, \
             independently of one another: {}.",
            category_descriptions.join("; "),
        ),
        locations: categorized
            .iter()
            .map(|item| item.location.clone())
            .collect(),
    };

    let evidence_identities: Vec<String> = items.iter().map(|item| item.name.clone()).collect();
    let id = PrincipleHeuristicId::compute(DesignPrinciple::Cohesion, &scope, &evidence_identities);

    PrincipleHeuristic {
        id,
        principle: DesignPrinciple::Cohesion,
        scope,
        evidence: vec![structural, category_evidence],
        interpretation: "This file defines several public items, and at least two of them \
            exhibit different effect categories (I/O, terminal output, complex computation) \
            independently of each other. That may indicate the file bundles more than one \
            responsibility."
            .to_string(),
        contraindications: vec![
            Contraindication {
                description: "A module deliberately organized as a small orchestration/facade \
                    layer may legitimately touch several effect kinds by design — that's its \
                    job, not a cohesion problem."
                    .to_string(),
            },
            Contraindication {
                description: "Three or more public items in one file is extremely common in \
                    Rust and not inherently a signal on its own without the category-diversity \
                    evidence."
                    .to_string(),
            },
        ],
        missing_evidence: vec![MissingEvidence {
            description: "Whether these items are actually called together/interdependently \
                (true coupling) or are just co-located is not checked here — only that they \
                exist in the same file with different effect signatures."
                .to_string(),
        }],
        alternatives: vec![
            DesignAlternative {
                description: "Keep the file as-is.".to_string(),
            },
            DesignAlternative {
                description: "Split the file along the observed effect-category boundaries \
                    into separate modules, each with a narrower responsibility."
                    .to_string(),
            },
        ],
        related_findings: Vec::new(),
    }
}

/// One method-chain expression [`law_of_demeter_candidates`] flags: its
/// length (number of chained `.method()` calls in the single unbroken
/// expression), the rendered source text of the whole chain, and the
/// rendered source text of each intermediate partial result strictly
/// between the full chain and its base receiver (used for signal 2 — see
/// that function's doc comment).
struct ChainHit {
    length: usize,
    rendered: String,
    intermediates: Vec<String>,
}

/// Whether `expr` (after unwrapping any leading `&`/`&mut`/parens) is the
/// kind of chain base [`law_of_demeter_candidates`] excludes before either
/// of its signals is even checked: a bare `self`, a one-level-deep
/// `self.field` access, an associated call on `Self::...`, or a
/// constructor-shaped associated call (`Type::new(...)`,
/// `Type::default(...)`, `Type::builder(...)`). `self.foo.bar()`-shaped
/// chains are ordinary Rust idiom, and a builder chain on a freshly
/// constructed local is a well-known, deliberate pattern — neither is a
/// Demeter concern.
fn chain_base_is_excluded(expr: &syn::Expr) -> bool {
    let mut cursor = expr;
    loop {
        match cursor {
            syn::Expr::Reference(reference) => cursor = reference.expr.as_ref(),
            syn::Expr::Paren(paren) => cursor = paren.expr.as_ref(),
            _ => break,
        }
    }
    match cursor {
        syn::Expr::Path(path) => path.path.is_ident("self"),
        syn::Expr::Field(field) => {
            matches!(field.base.as_ref(), syn::Expr::Path(base) if base.path.is_ident("self"))
        }
        syn::Expr::Call(call) => {
            let syn::Expr::Path(func_path) = call.func.as_ref() else {
                return false;
            };
            let segments: Vec<String> = func_path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect();
            if segments.first().map(String::as_str) == Some("Self") {
                return true;
            }
            segments.len() >= 2
                && matches!(
                    segments.last().map(String::as_str),
                    Some("new" | "default" | "builder")
                )
        }
        _ => false,
    }
}

/// Whether `block`'s own statements (not nested blocks) include a `let`
/// binding whose initializer renders to the same token text as one of
/// `intermediates` — signal 2 for [`law_of_demeter_candidates`]: a chain
/// whose intermediate results are already bound elsewhere in the same block
/// was made readable/broken up deliberately, which is not this heuristic's
/// concern.
fn has_intermediate_let(block: &syn::Block, intermediates: &[String]) -> bool {
    use quote::ToTokens;
    block.stmts.iter().any(|stmt| {
        if let syn::Stmt::Local(local) = stmt
            && let Some(init) = &local.init
        {
            intermediates.contains(&init.expr.to_token_stream().to_string())
        } else {
            false
        }
    })
}

/// Method-chain expressions in `block` matching [`law_of_demeter_candidates`]:
/// [`LAW_OF_DEMETER_CHAIN_THRESHOLD`] or more chained calls in one unbroken
/// expression, not starting from an excluded base
/// ([`chain_base_is_excluded`]), with no sibling `let` in the enclosing
/// block capturing an intermediate step ([`has_intermediate_let`]). Tracks
/// already-consumed inner `Expr::MethodCall` nodes by pointer identity so a
/// maximal chain is only reported once, at its outermost call — the same
/// "consumed" bookkeeping `slop_structural.rs`'s if/else-if chain walk uses
/// for the same reason (avoid re-evaluating an inner node of an already
/// reported chain as its own, shorter chain head).
fn law_of_demeter_chain_hits(block: &syn::Block) -> Vec<ChainHit> {
    use quote::ToTokens;

    struct Finder<'ast> {
        consumed: std::collections::HashSet<*const syn::ExprMethodCall>,
        block_stack: Vec<&'ast syn::Block>,
        hits: Vec<ChainHit>,
    }
    impl<'ast> Visit<'ast> for Finder<'ast> {
        fn visit_block(&mut self, node: &'ast syn::Block) {
            self.block_stack.push(node);
            syn::visit::visit_block(self, node);
            self.block_stack.pop();
        }

        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            if self
                .consumed
                .contains(&(node as *const syn::ExprMethodCall))
            {
                syn::visit::visit_expr_method_call(self, node);
                return;
            }

            let mut length = 1;
            let mut intermediates = Vec::new();
            let mut cursor: &syn::Expr = node.receiver.as_ref();
            while let syn::Expr::MethodCall(inner) = cursor {
                self.consumed.insert(inner as *const syn::ExprMethodCall);
                length += 1;
                intermediates.push(cursor.to_token_stream().to_string());
                cursor = inner.receiver.as_ref();
            }

            if length >= LAW_OF_DEMETER_CHAIN_THRESHOLD
                && !chain_base_is_excluded(cursor)
                && !self
                    .block_stack
                    .last()
                    .is_some_and(|block| has_intermediate_let(block, &intermediates))
            {
                self.hits.push(ChainHit {
                    length,
                    rendered: node.to_token_stream().to_string(),
                    intermediates,
                });
            }

            syn::visit::visit_expr_method_call(self, node);
        }

        fn visit_item_fn(&mut self, _node: &'ast syn::ItemFn) {}
    }

    let mut finder = Finder {
        consumed: std::collections::HashSet::new(),
        block_stack: Vec::new(),
        hits: Vec::new(),
    };
    finder.visit_block(block);
    finder.hits
}

/// Law of Demeter (todo.md §16.7's table): "Methodenkette über mehrere
/// Objektgrenzen (`a.b().c().d()`), kein `let` dazwischen" → "Tell-Don't-
/// Ask/Fassade statt tiefer Kettennavigation prüfen".
///
/// Two independent signals, both required on the same chain expression:
///
/// 1. **Structural (chain length)** — at least
///    [`LAW_OF_DEMETER_CHAIN_THRESHOLD`] chained `.method()` calls in one
///    unbroken expression, counted by walking nested `Expr::MethodCall`
///    receivers ([`law_of_demeter_chain_hits`]).
/// 2. **Corroborating (no readable breakdown already exists)** — no sibling
///    `let` binding in the same block captures the rendered text of any
///    intermediate step of the chain ([`has_intermediate_let`]). A chain
///    whose intermediate results are already bound elsewhere in the block is
///    evidence the steps were made readable/intentional, not a Demeter
///    concern.
///
/// Chains whose base receiver is `self`, `&self`/`&mut self`, a one-level
/// `self.field` access, an associated call on `Self::...`, or a
/// constructor-shaped associated call (`Type::new(...)`,
/// `Type::default(...)`, `Type::builder(...)`) are excluded before either
/// signal is even checked (see [`chain_base_is_excluded`]).
///
/// At most one heuristic per matching chain expression — a function may
/// contribute more than one if it contains several qualifying chains.
fn law_of_demeter_candidates(workspace: &Workspace) -> Vec<PrincipleHeuristic> {
    let mut heuristics = Vec::new();
    for krate in &workspace.crates {
        for source in &krate.source_files {
            let Ok(text) = std::fs::read_to_string(&source.path) else {
                continue;
            };
            let Ok(ast) = syn::parse_file(&text) else {
                continue;
            };
            walk_functions(&ast, |site| {
                for hit in law_of_demeter_chain_hits(site.block) {
                    heuristics.push(build_law_of_demeter_heuristic(
                        krate,
                        &source.path,
                        &site.qualified_name,
                        &hit,
                    ));
                }
            });
        }
    }
    heuristics
}

fn build_law_of_demeter_heuristic(
    krate: &CrateInfo,
    file: &Path,
    item_path: &str,
    hit: &ChainHit,
) -> PrincipleHeuristic {
    let scope = CodeScope {
        krate: krate.name.clone(),
        modules: vec![item_path.to_string()],
    };
    let location = EvidenceLocation {
        file: file.to_path_buf(),
        item_path: Some(item_path.to_string()),
    };

    let structural = Evidence {
        description: format!(
            "`{item_path}` contains a method chain with {} chained calls in one unbroken \
             expression, at or above the {LAW_OF_DEMETER_CHAIN_THRESHOLD}-call threshold this \
             heuristic treats as a long reach: `{}`.",
            hit.length, hit.rendered
        ),
        locations: vec![location.clone()],
    };
    let corroborating = Evidence {
        description: if hit.intermediates.is_empty() {
            "This chain has no intermediate step besides its base receiver to look for in a \
             sibling `let` binding."
                .to_string()
        } else {
            format!(
                "No sibling `let` binding elsewhere in the same block captures any of this \
                 chain's intermediate results ({}) — the chain was not already broken into \
                 readable steps.",
                hit.intermediates.join(", ")
            )
        },
        locations: vec![location],
    };

    let evidence_identities = vec![item_path.to_string(), hit.rendered.clone()];
    let id =
        PrincipleHeuristicId::compute(DesignPrinciple::LawOfDemeter, &scope, &evidence_identities);

    PrincipleHeuristic {
        id,
        principle: DesignPrinciple::LawOfDemeter,
        scope,
        evidence: vec![structural, corroborating],
        interpretation: format!(
            "In the examined function, this expression reaches through {} chained method calls \
             in a single unbroken step, without an intermediate binding that would suggest the \
             steps were deliberately made readable. That may indicate the caller depends on \
             more of an intermediate object's own interface than its immediate collaborator.",
            hit.length
        ),
        contraindications: vec![
            Contraindication {
                description: "A chain over a well-known, stable interface designed for chaining \
                    (iterator adaptors, string/path builders) is idiomatic Rust and not itself \
                    evidence of reaching through unrelated internals."
                    .to_string(),
            },
            Contraindication {
                description: "If every type in the chain belongs to the same module or is a \
                    thin wrapper around the previous step's own concern, the chain may not cross \
                    any real object boundary."
                    .to_string(),
            },
        ],
        missing_evidence: vec![MissingEvidence {
            description: "Whether the intermediate types in the chain belong to unrelated \
                ownership boundaries (the actual Demeter concern) or are closely related \
                collaborators is not checked here — only that the chain is long and unbroken."
                .to_string(),
        }],
        alternatives: vec![
            DesignAlternative {
                description: "Keep the expression as-is.".to_string(),
            },
            DesignAlternative {
                description: "Introduce intermediate `let` bindings, or a method on the \
                    immediate collaborator that performs the deeper step internally (Tell, \
                    Don't Ask), so the caller depends on one interface instead of several \
                    chained ones."
                    .to_string(),
            },
        ],
        related_findings: Vec::new(),
    }
}

/// One `loop { ... }` [`bounded_resources_loop_candidates`] flags: the
/// source line its `loop` keyword starts on.
struct LoopHit {
    line: usize,
}

/// Whether `path`'s segments contain the consecutive pair `process`, `exit`
/// anywhere — the same accepted-limitation, path-suffix matching
/// [`path_matches_io_prefix`] uses, applied to `std::process::exit`
/// specifically (also matches a `use`-imported bare `process::exit`).
fn path_matches_process_exit(path: &syn::Path) -> bool {
    let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
    segments
        .windows(2)
        .any(|pair| pair[0] == "process" && pair[1] == "exit")
}

/// Whether `body` (a `loop { ... }`'s own block) contains, anywhere within
/// its own lexical scope, a `break`, `return`, `?`, `panic!`, or
/// `std::process::exit(...)` call. Does not descend into a nested closure or
/// a locally defined `fn` item — a `break`/`return`/`?` inside either
/// targets that inner scope, not this loop. Still descends into a nested
/// `loop`/`while`/`for`, so an unlabeled `break` belonging only to an inner
/// loop is (conservatively) still counted as an exit for the outer loop —
/// see [`bounded_resources_loop_candidates`]'s `missing_evidence` for this
/// accepted limitation.
fn loop_has_any_exit(body: &syn::Block) -> bool {
    struct Finder {
        found: bool,
    }
    impl<'ast> Visit<'ast> for Finder {
        fn visit_expr_break(&mut self, node: &'ast syn::ExprBreak) {
            self.found = true;
            syn::visit::visit_expr_break(self, node);
        }

        fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
            self.found = true;
            syn::visit::visit_expr_return(self, node);
        }

        fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
            self.found = true;
            syn::visit::visit_expr_try(self, node);
        }

        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            if node.path.is_ident("panic") {
                self.found = true;
            }
            syn::visit::visit_macro(self, node);
        }

        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = node.func.as_ref()
                && path_matches_process_exit(&path.path)
            {
                self.found = true;
            }
            syn::visit::visit_expr_call(self, node);
        }

        fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {}

        fn visit_item_fn(&mut self, _node: &'ast syn::ItemFn) {}
    }
    let mut finder = Finder { found: false };
    finder.visit_block(body);
    finder.found
}

/// `loop { ... }` expressions in `block` with no visible exit at all in
/// their own lexical body ([`loop_has_any_exit`]) — see
/// [`bounded_resources_loop_candidates`] for why "no exit at all", not just
/// "no `break`", is required.
fn bounded_resources_loop_hits(block: &syn::Block) -> Vec<LoopHit> {
    struct Finder {
        hits: Vec<LoopHit>,
    }
    impl<'ast> Visit<'ast> for Finder {
        fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
            if !loop_has_any_exit(&node.body) {
                self.hits.push(LoopHit {
                    line: node.loop_token.span().start().line,
                });
            }
            syn::visit::visit_expr_loop(self, node);
        }

        fn visit_item_fn(&mut self, _node: &'ast syn::ItemFn) {}
    }
    let mut finder = Finder { hits: Vec::new() };
    finder.visit_block(block);
    finder.hits
}

fn bounded_resources_loop_candidates(workspace: &Workspace) -> Vec<PrincipleHeuristic> {
    let mut heuristics = Vec::new();
    for krate in &workspace.crates {
        for source in &krate.source_files {
            let Ok(text) = std::fs::read_to_string(&source.path) else {
                continue;
            };
            let Ok(ast) = syn::parse_file(&text) else {
                continue;
            };
            walk_functions(&ast, |site| {
                for hit in bounded_resources_loop_hits(site.block) {
                    heuristics.push(build_bounded_resources_loop_heuristic(
                        krate,
                        &source.path,
                        &site.qualified_name,
                        &hit,
                    ));
                }
            });
        }
    }
    heuristics
}

fn build_bounded_resources_loop_heuristic(
    krate: &CrateInfo,
    file: &Path,
    item_path: &str,
    hit: &LoopHit,
) -> PrincipleHeuristic {
    let scope = CodeScope {
        krate: krate.name.clone(),
        modules: vec![item_path.to_string()],
    };
    let location = EvidenceLocation {
        file: file.to_path_buf(),
        item_path: Some(item_path.to_string()),
    };

    let structural = Evidence {
        description: format!(
            "`{item_path}` has a `loop {{ ... }}` at line {} with no `break` anywhere in its \
             own lexical body (not counting a nested closure or a locally defined nested `fn`).",
            hit.line
        ),
        locations: vec![location.clone()],
    };
    let corroborating = Evidence {
        description: "The same loop also has no `return`, `?`, `panic!`, or \
            `std::process::exit` anywhere in its own lexical body — no visible exit path at \
            all, not just an absent `break`."
            .to_string(),
        locations: vec![location],
    };

    let evidence_identities = vec![item_path.to_string(), hit.line.to_string()];
    let id = PrincipleHeuristicId::compute(
        DesignPrinciple::BoundedResources,
        &scope,
        &evidence_identities,
    );

    PrincipleHeuristic {
        id,
        principle: DesignPrinciple::BoundedResources,
        scope,
        evidence: vec![structural, corroborating],
        interpretation: "In the examined function, this `loop` has no visible exit — no \
            `break`, `return`, `?`, `panic!`, or `std::process::exit` — anywhere in its own \
            lexical body. That may indicate the loop's termination depends on something this \
            per-function, syntax-only check cannot see, or that the loop is genuinely \
            unbounded."
            .to_string(),
        contraindications: vec![
            Contraindication {
                description: "A loop meant to run for the process's entire lifetime (an event \
                    loop, a server accept loop) is deliberately unbounded — that's its job, not \
                    a defect."
                    .to_string(),
            },
            Contraindication {
                description: "This is a Fast-Tier syntax proxy, not a termination proof: an \
                    exit driven by a called function's own control flow (e.g. a helper that \
                    itself calls `std::process::exit`) would not be seen here."
                    .to_string(),
            },
        ],
        missing_evidence: vec![MissingEvidence {
            description: "Whether this loop is an intentional long-running loop versus a \
                genuine bug is not distinguished here — that depends on non-observable intent. \
                A `break` reached only via a labeled block/loop from further out, or an \
                unlabeled `break` belonging only to a nested inner loop (still conservatively \
                counted as this loop's own exit), would not be recognized correctly by this \
                check."
                .to_string(),
        }],
        alternatives: vec![
            DesignAlternative {
                description: "Keep the loop as-is.".to_string(),
            },
            DesignAlternative {
                description: "Make the loop's bound or termination condition explicit — a \
                    `while`/`for` with a visible bound, an explicit `break` condition, or a \
                    documented comment explaining why the loop is intentionally unbounded."
                    .to_string(),
            },
        ],
        related_findings: Vec::new(),
    }
}

/// One directly self-recursive function
/// [`bounded_resources_recursion_candidates`] flags: how many call sites
/// call the function by its own name, the rendered text and line of the
/// first one, and the function's own parameter names (used to phrase signal
/// 2's evidence — see that function's doc comment).
struct RecursionHit {
    call_count: usize,
    first_call_rendered: String,
    first_call_line: usize,
    param_names: Vec<String>,
}

/// Whether `expr` references any identifier in `names` anywhere within it —
/// duplicated from `crate::pattern::expr_references_ident` (generalized to a
/// name list) for the same reason this module's other helpers duplicate
/// `pattern.rs`/`boundaries.rs` internals rather than making them `pub`.
fn expr_references_any(expr: &syn::Expr, names: &[String]) -> bool {
    struct Finder<'a> {
        names: &'a [String],
        found: bool,
    }
    impl<'ast> Visit<'ast> for Finder<'_> {
        fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
            if let Some(ident) = node.path.get_ident() {
                let name = ident.to_string();
                if self.names.contains(&name) {
                    self.found = true;
                }
            }
            syn::visit::visit_expr_path(self, node);
        }
    }
    let mut finder = Finder {
        names,
        found: false,
    };
    finder.visit_expr(expr);
    finder.found
}

/// Every call site in `block` that calls the function named `name` by its
/// own name — either a free/associated call (`name(...)`, `Self::name(...)`,
/// `Type::name(...)`) or a method call (`x.name(...)`) — paired with the
/// call's source line, sorted in source order. Ignores indirect/mutual
/// recursion (a function calling a *different* function that calls back
/// into this one) — too expensive to detect with pure per-file AST, and out
/// of scope for this Fast-Tier proxy. Does not descend into a locally
/// defined nested `fn` of the same name (that would be a shadowing,
/// unrelated function).
fn direct_recursive_calls(block: &syn::Block, name: &str) -> Vec<(usize, String)> {
    use quote::ToTokens;

    struct Finder<'a> {
        name: &'a str,
        hits: Vec<(usize, String)>,
    }
    impl<'ast> Visit<'ast> for Finder<'_> {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = node.func.as_ref()
                && path
                    .path
                    .segments
                    .last()
                    .is_some_and(|s| s.ident == self.name)
            {
                self.hits
                    .push((node.span().start().line, node.to_token_stream().to_string()));
            }
            syn::visit::visit_expr_call(self, node);
        }

        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            if node.method == self.name {
                self.hits
                    .push((node.span().start().line, node.to_token_stream().to_string()));
            }
            syn::visit::visit_expr_method_call(self, node);
        }

        fn visit_item_fn(&mut self, _node: &'ast syn::ItemFn) {}
    }
    let mut finder = Finder {
        name,
        hits: Vec::new(),
    };
    finder.visit_block(block);
    finder.hits.sort_by_key(|(line, _)| *line);
    finder.hits
}

/// Parameter identifiers of `sig` — simple `Pat::Ident` patterns only
/// (destructuring patterns are skipped, an accepted limitation), excluding
/// the receiver.
fn param_names(sig: &syn::Signature) -> Vec<String> {
    sig.inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Typed(pat_type) => match pat_type.pat.as_ref() {
                syn::Pat::Ident(pat_ident) => Some(pat_ident.ident.to_string()),
                _ => None,
            },
            syn::FnArg::Receiver(_) => None,
        })
        .collect()
}

/// Whether `block` contains an `if`/`match` whose condition/scrutinee
/// references any of `params`, at a line strictly before `before_line` —
/// signal 2 for [`bounded_resources_recursion_candidates`]'s recursion
/// case. Does not descend into a locally defined nested `fn` item, the same
/// exclusion [`direct_recursive_calls`] uses.
fn has_parameter_guard_before(block: &syn::Block, params: &[String], before_line: usize) -> bool {
    struct Finder<'a> {
        params: &'a [String],
        before_line: usize,
        found: bool,
    }
    impl<'ast> Visit<'ast> for Finder<'_> {
        fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
            if node.if_token.span().start().line < self.before_line
                && expr_references_any(&node.cond, self.params)
            {
                self.found = true;
            }
            syn::visit::visit_expr_if(self, node);
        }

        fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
            if node.match_token.span().start().line < self.before_line
                && expr_references_any(&node.expr, self.params)
            {
                self.found = true;
            }
            syn::visit::visit_expr_match(self, node);
        }

        fn visit_item_fn(&mut self, _node: &'ast syn::ItemFn) {}
    }
    let mut finder = Finder {
        params,
        before_line,
        found: false,
    };
    finder.visit_block(block);
    finder.found
}

/// Builds a [`RecursionHit`] for one function named `name` if it directly
/// calls itself ([`direct_recursive_calls`]) with no parameter-referencing
/// `if`/`match` visible before the first such call
/// ([`has_parameter_guard_before`]) — the two independent signals
/// [`bounded_resources_recursion_candidates`]'s recursion case requires.
fn bounded_resources_recursion_hit(
    name: &str,
    sig: &syn::Signature,
    block: &syn::Block,
) -> Option<RecursionHit> {
    let calls = direct_recursive_calls(block, name);
    let (first_call_line, first_call_rendered) = calls.first()?.clone();
    let params = param_names(sig);
    if has_parameter_guard_before(block, &params, first_call_line) {
        return None;
    }
    Some(RecursionHit {
        call_count: calls.len(),
        first_call_rendered,
        first_call_line,
        param_names: params,
    })
}

fn bounded_resources_recursion_candidates(workspace: &Workspace) -> Vec<PrincipleHeuristic> {
    let mut heuristics = Vec::new();
    for krate in &workspace.crates {
        for source in &krate.source_files {
            let Ok(text) = std::fs::read_to_string(&source.path) else {
                continue;
            };
            let Ok(ast) = syn::parse_file(&text) else {
                continue;
            };
            let mut hits: Vec<(String, RecursionHit)> = Vec::new();
            walk_functions(&ast, |site| {
                // Trait default methods have no `vis` of their own — skip
                // them, matching the pre-migration hand-rolled visitor,
                // which never visited `TraitItemFn` bodies for this check.
                if site.vis.is_none() {
                    return;
                }
                let name = site.sig.ident.to_string();
                if let Some(hit) = bounded_resources_recursion_hit(&name, site.sig, site.block) {
                    hits.push((site.qualified_name.clone(), hit));
                }
            });
            for (item_path, hit) in hits {
                heuristics.push(build_bounded_resources_recursion_heuristic(
                    krate,
                    &source.path,
                    &item_path,
                    &hit,
                ));
            }
        }
    }
    heuristics
}

fn build_bounded_resources_recursion_heuristic(
    krate: &CrateInfo,
    file: &Path,
    item_path: &str,
    hit: &RecursionHit,
) -> PrincipleHeuristic {
    let scope = CodeScope {
        krate: krate.name.clone(),
        modules: vec![item_path.to_string()],
    };
    let location = EvidenceLocation {
        file: file.to_path_buf(),
        item_path: Some(item_path.to_string()),
    };

    let structural = Evidence {
        description: format!(
            "`{item_path}` calls itself directly by name at least once (line {}: `{}`, {} \
             recursive call site(s) total).",
            hit.first_call_line, hit.first_call_rendered, hit.call_count
        ),
        locations: vec![location.clone()],
    };
    let corroborating = Evidence {
        description: if hit.param_names.is_empty() {
            format!(
                "`{item_path}` takes no parameters, so no parameter-derived guard is possible \
                 before the recursive call at line {}.",
                hit.first_call_line
            )
        } else {
            format!(
                "No `if`/`match` in `{item_path}` references one of its own parameters ({}) at \
                 a line before the recursive call at line {} — no visible parameter-derived \
                 guard precedes it.",
                hit.param_names.join(", "),
                hit.first_call_line
            )
        },
        locations: vec![location],
    };

    let evidence_identities = vec![item_path.to_string()];
    let id = PrincipleHeuristicId::compute(
        DesignPrinciple::BoundedResources,
        &scope,
        &evidence_identities,
    );

    PrincipleHeuristic {
        id,
        principle: DesignPrinciple::BoundedResources,
        scope,
        evidence: vec![structural, corroborating],
        interpretation: "In the examined function, direct self-recursion occurs with no \
            parameter-referencing `if`/`match` visible before the recursive call. That may \
            indicate the recursion has no syntactically visible base case, though this \
            per-function, syntax-only check cannot rule out a guard expressed another way."
            .to_string(),
        contraindications: vec![
            Contraindication {
                description: "A base case guarded by a helper function's return value, a field \
                    access reached indirectly rather than a bare parameter reference, or a \
                    guard expressed via an early `?`/error return would not be recognized by \
                    this check."
                    .to_string(),
            },
            Contraindication {
                description: "Mutual/indirect recursion through another function is out of \
                    scope for this per-file, name-based check — a real base case reached that \
                    way looks identical to no base case at all here."
                    .to_string(),
            },
        ],
        missing_evidence: vec![MissingEvidence {
            description: "Whether the recursion is actually bounded by something this check \
                can't see (a helper's return value, a field access rather than a bare \
                parameter reference, or an externally enforced call-depth limit) is not \
                checked here — only that no parameter-referencing conditional textually \
                precedes the first recursive call."
                .to_string(),
        }],
        alternatives: vec![
            DesignAlternative {
                description: "Keep the function as-is.".to_string(),
            },
            DesignAlternative {
                description: "Add an explicit guard on a parameter (or a value derived from \
                    one) before the recursive call, or convert the recursion to an explicitly \
                    bounded iterative loop."
                    .to_string(),
            },
        ],
        related_findings: Vec::new(),
    }
}

/// Bounded Resources (todo.md §16.7's table): "unbegrenzte Iteration/
/// Rekursion ohne erkennbare Terminierungsbedingung" → "Terminierungs-
/// /Bound-Beweis nachrüsten".
///
/// A Fast-Tier **syntax-only proxy**, not a whole-program termination proof
/// (that would need Deep Tier dataflow, out of scope here) — the same
/// "proxy, not proof" framing `integer-cast-risk`/`unsafe-surface` use for
/// their own Fast-Tier signals. Two structurally different shapes, each
/// requiring two independent signals on the same site:
///
/// 1. **An unconditional `loop { ... }` with no visible exit at all** — see
///    [`bounded_resources_loop_candidates`]. A `while`/`for` loop already
///    has a syntactic bound expression, so only `loop` is considered.
/// 2. **A directly self-recursive function with no visible parameter guard**
///    — see [`bounded_resources_recursion_candidates`]. Only direct
///    self-recursion (a function calling itself by name) is considered;
///    mutual/indirect recursion is out of scope for a per-file AST check.
///
/// Both shapes are intentionally narrow and will miss real unbounded loops/
/// recursion and flag some fine code — see each builder function's
/// `contraindications`/`missing_evidence` for exactly what's out of scope. A
/// low-frequency, high-precision result is the expected, correct outcome
/// here, not a bug to loosen the signals over.
fn bounded_resources_candidates(workspace: &Workspace) -> Vec<PrincipleHeuristic> {
    let mut heuristics = bounded_resources_loop_candidates(workspace);
    heuristics.extend(bounded_resources_recursion_candidates(workspace));
    heuristics
}

/// Leaf identifiers [`primitive_scalar_kind`] recognizes as a "primitive/
/// string" shape — Rust's built-in scalar types plus `str`/`String`. Kept as
/// a fixed, narrow list rather than any type-resolution: this is a
/// syntactic proxy, the same accepted-limitation approach every other
/// detector in this module uses for type/path matching.
const PRIMITIVE_SCALAR_IDENTS: &[&str] = &[
    "str", "String", "bool", "char", "i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16",
    "u32", "u64", "u128", "usize", "f32", "f64",
];

/// Whether `ty` is (optionally through one layer of `&`) one of
/// [`PRIMITIVE_SCALAR_IDENTS`] — matched purely by the type's leaf segment
/// identifier, not full path/type resolution. Canonicalizes `String` to the
/// same `"str"` kind as `str`/`&str`, since both represent the same
/// "textual, not yet parsed into a distinct shape" family for
/// [`parse_dont_validate_candidates`]'s purposes.
fn primitive_scalar_kind(ty: &syn::Type) -> Option<String> {
    let inner = match ty {
        syn::Type::Reference(reference) => reference.elem.as_ref(),
        other => other,
    };
    let syn::Type::Path(type_path) = inner else {
        return None;
    };
    let ident = type_path.path.segments.last()?.ident.to_string();
    if !PRIMITIVE_SCALAR_IDENTS.contains(&ident.as_str()) {
        return None;
    }
    Some(if ident == "String" {
        "str".to_string()
    } else {
        ident
    })
}

/// [`primitive_scalar_kind`] of `sig`'s return type, unwrapping one layer of
/// `Result<T, _>`/`Option<T>` first so a function returning e.g.
/// `Result<&str, Error>` is still recognized as "still the same loosely-
/// typed shape" rather than treated as if it returned the error type. A
/// function with no return type (`-> ()`), or one whose return type's leaf
/// identifier isn't a primitive/string/bool at all, yields `None` — the
/// latter is exactly the "already parses into a distinct newtype, don't
/// flag it" exclusion [`parse_dont_validate_candidates`] depends on.
fn return_scalar_kind(output: &syn::ReturnType) -> Option<String> {
    let syn::ReturnType::Type(_, ty) = output else {
        return None;
    };
    if let Some(kind) = primitive_scalar_kind(ty) {
        return Some(kind);
    }
    let syn::Type::Path(type_path) = ty.as_ref() else {
        return None;
    };
    let segment = type_path.path.segments.last()?;
    if segment.ident != "Result" && segment.ident != "Option" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };
    let first_type = args.args.iter().find_map(|arg| match arg {
        syn::GenericArgument::Type(inner) => Some(inner),
        _ => None,
    })?;
    primitive_scalar_kind(first_type)
}

/// `(name, type)` for every simple `Pat::Ident` parameter of `sig`,
/// excluding the receiver — the same destructuring-pattern limitation as
/// [`param_names`], but keeping the type alongside the name since
/// [`parse_dont_validate_candidates`] needs both.
fn typed_params(sig: &syn::Signature) -> Vec<(String, &syn::Type)> {
    sig.inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Typed(pat_type) => match pat_type.pat.as_ref() {
                syn::Pat::Ident(pat_ident) => {
                    Some((pat_ident.ident.to_string(), pat_type.ty.as_ref()))
                }
                _ => None,
            },
            syn::FnArg::Receiver(_) => None,
        })
        .collect()
}

/// Whether `block` (or, via [`Visit::visit_expr`], a single match arm's
/// body) contains a `return`, anywhere in its own lexical scope, or a call
/// to the `panic!` macro — the "guard actually exits" half of a validation-
/// shaped check. Does not descend into a nested closure or a locally
/// defined nested `fn`, the same exclusion [`loop_has_any_exit`] uses.
struct ReturnOrPanicFinder {
    found: bool,
}

impl<'ast> Visit<'ast> for ReturnOrPanicFinder {
    fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
        self.found = true;
        syn::visit::visit_expr_return(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node.path.is_ident("panic") {
            self.found = true;
        }
        syn::visit::visit_macro(self, node);
    }

    fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {}

    fn visit_item_fn(&mut self, _node: &'ast syn::ItemFn) {}
}

fn block_has_return_or_panic(block: &syn::Block) -> bool {
    let mut finder = ReturnOrPanicFinder { found: false };
    finder.visit_block(block);
    finder.found
}

fn expr_has_return_or_panic(expr: &syn::Expr) -> bool {
    let mut finder = ReturnOrPanicFinder { found: false };
    finder.visit_expr(expr);
    finder.found
}

/// Whether `path` names one of the `assert!`/`assert_eq!`/`assert_ne!`
/// family (including the `debug_` variants) — [`validation_guard_hit`]'s
/// third guard shape, alongside `if`/`match`.
fn path_is_assert_like(path: &syn::Path) -> bool {
    const ASSERT_MACROS: &[&str] = &[
        "assert",
        "assert_eq",
        "assert_ne",
        "debug_assert",
        "debug_assert_eq",
        "debug_assert_ne",
    ];
    path.get_ident()
        .is_some_and(|ident| ASSERT_MACROS.contains(&ident.to_string().as_str()))
}

/// Whether `macro_call`'s own token stream mentions `param` as a whole
/// identifier — a crude, purely textual check (split on non-identifier
/// characters and compare), since `assert!`/`assert_eq!` bodies are
/// arbitrary token trees `syn` doesn't parse as an `Expr` by default. The
/// same accepted-limitation trade-off other detectors in this module make
/// for macro-body matching.
fn macro_tokens_reference_param(macro_call: &syn::Macro, param: &str) -> bool {
    macro_call
        .tokens
        .to_string()
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|token| token == param)
}

/// One validation-shaped guard [`validation_guard_hit`] found on a single
/// parameter: the source line the guard starts on, and a rendered
/// (`quote`-token-stream) snippet of the condition/macro for evidence text.
struct ValidationGuard {
    line: usize,
    rendered: String,
}

/// Finds a validation-shaped guard on `param` in `block`: an `if` whose
/// condition references `param` and whose then-branch contains a `return`
/// or `panic!` ([`block_has_return_or_panic`]); a `match` whose scrutinee
/// references `param` and at least one arm's body contains a `return` or
/// `panic!` ([`expr_has_return_or_panic`]); or a bare `assert!`/`assert_eq!`/
/// `assert_ne!` (or `debug_` variant) macro call whose tokens mention
/// `param` ([`macro_tokens_reference_param`]). Returns the first such guard
/// found in source order; does not descend into a nested closure or locally
/// defined nested `fn`, the same exclusion [`has_parameter_guard_before`]
/// uses.
fn validation_guard_hit(block: &syn::Block, param: &str) -> Option<ValidationGuard> {
    use quote::ToTokens;

    struct Finder<'a> {
        param: &'a str,
        hit: Option<ValidationGuard>,
    }
    impl<'ast> Visit<'ast> for Finder<'_> {
        fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
            if self.hit.is_none()
                && expr_references_any(&node.cond, std::slice::from_ref(&self.param.to_string()))
                && block_has_return_or_panic(&node.then_branch)
            {
                self.hit = Some(ValidationGuard {
                    line: node.if_token.span().start().line,
                    rendered: node.cond.to_token_stream().to_string(),
                });
            }
            syn::visit::visit_expr_if(self, node);
        }

        fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
            if self.hit.is_none()
                && expr_references_any(&node.expr, std::slice::from_ref(&self.param.to_string()))
                && node
                    .arms
                    .iter()
                    .any(|arm| expr_has_return_or_panic(&arm.body))
            {
                self.hit = Some(ValidationGuard {
                    line: node.match_token.span().start().line,
                    rendered: node.expr.to_token_stream().to_string(),
                });
            }
            syn::visit::visit_expr_match(self, node);
        }

        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            if self.hit.is_none()
                && path_is_assert_like(&node.path)
                && macro_tokens_reference_param(node, self.param)
            {
                self.hit = Some(ValidationGuard {
                    line: node.path.span().start().line,
                    rendered: node.tokens.to_string(),
                });
            }
            syn::visit::visit_macro(self, node);
        }

        fn visit_item_fn(&mut self, _node: &'ast syn::ItemFn) {}
    }
    let mut finder = Finder { param, hit: None };
    finder.visit_block(block);
    finder.hit
}

/// Signal 1's result for one function: the primitive/string parameter that
/// carries a validation-shaped guard, alongside the function's own
/// still-primitive/string/bool return kind — see
/// [`parse_dont_validate_candidates`].
struct ParamGuardHit {
    param_name: String,
    param_kind: String,
    return_kind: String,
    guard_line: usize,
    guard_rendered: String,
}

/// Signal 1, in full: `sig`'s return type must itself still be a primitive/
/// string/bool shape ([`return_scalar_kind`] — this is what excludes a
/// function that already parses into a distinct newtype), and at least one
/// of `sig`'s primitive/string parameters must carry a validation-shaped
/// guard in `block` ([`validation_guard_hit`]). Returns the first such
/// parameter in signature order.
fn parse_dont_validate_signal1(sig: &syn::Signature, block: &syn::Block) -> Option<ParamGuardHit> {
    let return_kind = return_scalar_kind(&sig.output)?;
    for (name, ty) in typed_params(sig) {
        let param_kind = primitive_scalar_kind(ty)?;
        if let Some(guard) = validation_guard_hit(block, &name) {
            return Some(ParamGuardHit {
                param_name: name,
                param_kind,
                return_kind: return_kind.clone(),
                guard_line: guard.line,
                guard_rendered: guard.rendered,
            });
        }
    }
    None
}

/// A weaker, visibility-independent reading of the same guard shape signal
/// 1 uses, without signal 1's own return-type gate — every primitive/string
/// parameter of `sig` that carries a validation-shaped guard in `block`,
/// regardless of the function's own return type or visibility. Feeds
/// [`parse_dont_validate_candidates`]'s crate-wide signal 2 aggregation,
/// which is deliberately broader than signal 1: a private helper doing the
/// same kind of validation, even one that doesn't itself qualify as a
/// signal-1 candidate, still counts as evidence that the check is
/// duplicated across the crate instead of centralized into one parse step.
fn parse_dont_validate_guard_kinds(sig: &syn::Signature, block: &syn::Block) -> Vec<String> {
    typed_params(sig)
        .into_iter()
        .filter_map(|(name, ty)| {
            let kind = primitive_scalar_kind(ty)?;
            validation_guard_hit(block, &name).map(|_| kind)
        })
        .collect()
}

/// One other function in the crate, found by
/// [`parse_dont_validate_guard_kinds`], that also validates a parameter of
/// a given primitive kind — [`parse_dont_validate_candidates`]'s signal 2
/// corroboration for one particular candidate function.
struct GuardedParam {
    qualified_name: String,
    param_kind: String,
}

/// Parse, Don't Validate (todo.md §16.7's table; the Rust-community idiom
/// popularized by Alexis King's essay of the same name): a function that
/// repeatedly re-checks a primitive/string value's shape via runtime
/// control flow but hands the caller back the same loosely-typed value,
/// instead of parsing it once into a distinct, more precisely-typed
/// newtype/struct that makes the invalid state statically unrepresentable
/// downstream.
///
/// Two independent signals, both required:
///
/// 1. **Structural, single-function** ([`parse_dont_validate_signal1`]) — a
///    `pub fn` (chosen over "any `fn`" because the principle matters most at
///    an API boundary, where a caller can't see the validation logic behind
///    the call) with a primitive/string parameter guarded by validation-
///    shaped control flow (an `if`/`match` with an early `return`/`panic!`,
///    or a bare `assert!`-family call, referencing that parameter), whose
///    own return type is *still* a primitive/string/bool shape rather than
///    a distinct named type. That last condition is also this detector's
///    main built-in exclusion: a function that validates and then returns
///    `Result<NewType, _>`/`Option<NewType>` for some distinct `NewType` is
///    already doing Parse, Don't Validate correctly and is never flagged —
///    [`return_scalar_kind`] returns `None` for it.
/// 2. **Usage-based, crate-wide** ([`parse_dont_validate_guard_kinds`]) — the
///    same crate contains at least one *other*, independently written
///    function that also guards a parameter of the same primitive kind with
///    a validation-shaped check. This detector picks the "duplicated
///    validation logic" framing over the alternative "the caller re-
///    validates the value coming back from this function" framing: tracing
///    a value from a call site back through the caller's own control flow
///    is a dataflow question `syn` alone can't answer without overreaching
///    into semantic analysis, while "does this crate have more than one
///    function independently re-implementing the same shape of guard on the
///    same primitive type" is fully syntactic and checkable per-file. It's
///    also the more direct evidence for the actual concern: one function
///    validating a primitive is unremarkable input sanitization on its own,
///    but the *same* validation shape recurring across independent call
///    sites for the same primitive kind is what suggests the check was
///    never centralized into a single parse step in the first place.
///
/// A Fast-Tier syntactic proxy, not a semantic/dataflow analysis — like
/// every other detector in this module, narrow and precision-biased rather
/// than exhaustive; see [`build_parse_dont_validate_heuristic`]'s
/// `contraindications`/`missing_evidence` for what's out of scope.
fn parse_dont_validate_candidates(workspace: &Workspace) -> Vec<PrincipleHeuristic> {
    let mut heuristics = Vec::new();
    for krate in &workspace.crates {
        let mut guarded: Vec<GuardedParam> = Vec::new();
        for source in &krate.source_files {
            let Ok(text) = std::fs::read_to_string(&source.path) else {
                continue;
            };
            let Ok(ast) = syn::parse_file(&text) else {
                continue;
            };
            walk_functions(&ast, |site| {
                for param_kind in parse_dont_validate_guard_kinds(site.sig, site.block) {
                    guarded.push(GuardedParam {
                        qualified_name: site.qualified_name.clone(),
                        param_kind,
                    });
                }
            });
        }

        for source in &krate.source_files {
            let Ok(text) = std::fs::read_to_string(&source.path) else {
                continue;
            };
            let Ok(ast) = syn::parse_file(&text) else {
                continue;
            };
            walk_functions(&ast, |site| {
                if !matches!(site.vis, Some(syn::Visibility::Public(_))) {
                    return;
                }
                let Some(hit) = parse_dont_validate_signal1(site.sig, site.block) else {
                    return;
                };
                let mut siblings: Vec<String> = guarded
                    .iter()
                    .filter(|g| {
                        g.param_kind == hit.param_kind && g.qualified_name != site.qualified_name
                    })
                    .map(|g| g.qualified_name.clone())
                    .collect();
                siblings.sort();
                siblings.dedup();
                if siblings.is_empty() {
                    return;
                }
                heuristics.push(build_parse_dont_validate_heuristic(
                    krate,
                    &source.path,
                    &site.qualified_name,
                    &hit,
                    &siblings,
                ));
            });
        }
    }
    heuristics
}

fn build_parse_dont_validate_heuristic(
    krate: &CrateInfo,
    file: &Path,
    item_path: &str,
    hit: &ParamGuardHit,
    siblings: &[String],
) -> PrincipleHeuristic {
    let scope = CodeScope {
        krate: krate.name.clone(),
        modules: vec![item_path.to_string()],
    };
    let location = EvidenceLocation {
        file: file.to_path_buf(),
        item_path: Some(item_path.to_string()),
    };

    let structural = Evidence {
        description: format!(
            "`{item_path}` takes a `{}`-shaped parameter `{}` guarded by a validation-shaped \
             check at line {} (`{}`), and its own return type is still a `{}`-shaped value \
             rather than a distinct named type.",
            hit.param_kind, hit.param_name, hit.guard_line, hit.guard_rendered, hit.return_kind
        ),
        locations: vec![location.clone()],
    };
    let corroborating = Evidence {
        description: format!(
            "Elsewhere in crate `{}`, {} other function(s) independently guard a parameter of \
             the same `{}` kind with a similarly shaped validation check, instead of one shared \
             parse step: {}.",
            krate.name,
            siblings.len(),
            hit.param_kind,
            siblings.join(", ")
        ),
        locations: vec![location],
    };

    let evidence_identities = vec![item_path.to_string(), hit.param_name.clone()];
    let id = PrincipleHeuristicId::compute(
        DesignPrinciple::ParseDontValidate,
        &scope,
        &evidence_identities,
    );

    PrincipleHeuristic {
        id,
        principle: DesignPrinciple::ParseDontValidate,
        scope,
        evidence: vec![structural, corroborating],
        interpretation: format!(
            "In the examined function, parameter `{}` is checked at the boundary but the \
             function hands back the same loosely-typed `{}` shape, and a similarly shaped \
             check recurs on the same primitive kind elsewhere in the crate. That combination \
             may suggest the validation could be centralized into a single parse step that \
             returns a more precisely typed value, rather than repeated at each call site.",
            hit.param_name, hit.param_kind
        ),
        contraindications: vec![
            Contraindication {
                description: "A validation predicate meant to stay a reusable, general-purpose \
                    yes/no check (e.g. a small `is_valid`/`looks_like` helper called from several \
                    unrelated contexts) is a reasonable design on its own and not necessarily \
                    evidence that a boundary parse step is missing."
                    .to_string(),
            },
            Contraindication {
                description: "The sibling functions this heuristic points to may validate \
                    different, unrelated properties of the same primitive kind (e.g. one checks \
                    length, another checks character set) rather than duplicating the same check \
                    — this detector only compares primitive kind, not what the check actually \
                    verifies."
                    .to_string(),
            },
        ],
        missing_evidence: vec![MissingEvidence {
            description: "Whether the sibling functions this heuristic points to actually \
                duplicate the same semantic check, and whether a caller of the examined function \
                re-validates the value it gets back, are not checked here — only that a \
                similarly shaped guard recurs on the same primitive kind somewhere else in the \
                crate."
                .to_string(),
        }],
        alternatives: vec![
            DesignAlternative {
                description: "Keep the function as-is.".to_string(),
            },
            DesignAlternative {
                description: "Introduce a newtype/struct that performs the validation once in a \
                    constructor (or a `TryFrom`/`FromStr` impl) and carries the result, so \
                    downstream callers and the sibling functions this heuristic points to can \
                    depend on a value whose shape already guarantees the check passed."
                    .to_string(),
            },
        ],
        related_findings: Vec::new(),
    }
}

/// Whether any attribute in `attrs` is `#[non_exhaustive]` — the exact
/// syntax fact `api_surface::has_non_exhaustive` also turns on, duplicated
/// here for the same reason this module's other helpers duplicate
/// `pattern.rs`/`boundaries.rs`/`api_surface.rs` internals rather than
/// making them `pub`.
fn struct_has_non_exhaustive(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .any(|attr| attr.path().is_ident("non_exhaustive"))
}

/// Number of fields `fields` declares, regardless of shape (named, tuple, or
/// unit).
fn field_count(fields: &syn::Fields) -> usize {
    match fields {
        syn::Fields::Named(named) => named.named.len(),
        syn::Fields::Unnamed(unnamed) => unnamed.unnamed.len(),
        syn::Fields::Unit => 0,
    }
}

/// Whether every field in `fields` is `pub` — a struct with any private
/// field already forces construction through some non-literal path in most
/// cases, so [`api_evolvability_candidates`]'s signal 1 only considers
/// fully-open structs (see that function's doc comment).
fn all_fields_public(fields: &syn::Fields) -> bool {
    let vis_iter: Box<dyn Iterator<Item = &syn::Visibility>> = match fields {
        syn::Fields::Named(named) => Box::new(named.named.iter().map(|f| &f.vis)),
        syn::Fields::Unnamed(unnamed) => Box::new(unnamed.unnamed.iter().map(|f| &f.vis)),
        syn::Fields::Unit => Box::new(std::iter::empty()),
    };
    vis_iter
        .into_iter()
        .all(|vis| matches!(vis, syn::Visibility::Public(_)))
}

/// A `pub struct` declaration found while scanning a crate for
/// [`api_evolvability_candidates`]'s signal 1: its name, field count, and
/// where it's declared. Only structs whose fields are *all* `pub`, with no
/// `#[non_exhaustive]` attribute, and at least
/// [`API_EVOLVABILITY_MIN_FIELDS`] fields are collected — see that
/// function's doc comment.
struct EvolvableStructCandidate {
    name: String,
    field_count: usize,
    location: EvidenceLocation,
}

/// Collects [`EvolvableStructCandidate`]s in one parsed file — a small,
/// scope-specific `Visit` impl in the same style as this module's other
/// structural collectors (e.g. `DeclaredItemCollector`, interface
/// segregation's `Collector`), used instead of
/// [`crate::dead_code::walk_type_items`] because that walker's
/// `TypeItemSite` only carries a struct's qualified name/span/visibility —
/// not its field list or attributes, both of which this signal needs.
struct EvolvableStructCollector {
    file: PathBuf,
    candidates: Vec<EvolvableStructCandidate>,
}

impl<'ast> Visit<'ast> for EvolvableStructCollector {
    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        if matches!(node.vis, syn::Visibility::Public(_))
            && !struct_has_non_exhaustive(&node.attrs)
            && all_fields_public(&node.fields)
        {
            let count = field_count(&node.fields);
            if count >= API_EVOLVABILITY_MIN_FIELDS {
                self.candidates.push(EvolvableStructCandidate {
                    name: node.ident.to_string(),
                    field_count: count,
                    location: EvidenceLocation {
                        file: self.file.clone(),
                        item_path: Some(node.ident.to_string()),
                    },
                });
            }
        }
        syn::visit::visit_item_struct(self, node);
    }
}

/// One struct-literal construction expression (`Foo { a: x, b: y, .. }`)
/// found while scanning a crate for [`api_evolvability_candidates`]'s signal
/// 2: which struct type it names (matched by last path segment only, the
/// same accepted-limitation approach as [`path_matches_io_prefix`]) and
/// where it appears.
struct StructConstructionSite {
    type_name: String,
    line: usize,
    location: EvidenceLocation,
}

/// Collects [`StructConstructionSite`]s in one parsed file: every
/// `syn::Expr::Struct` with at least one explicit field. A construction that
/// is *only* a `..` spread (`Foo { ..Default::default() }`, zero explicit
/// fields) is excluded — it demonstrates nothing about reliance on the
/// struct's exact field set. A construction with at least one explicit field
/// plus a partial `..` spread still counts, since the explicit field is
/// still coupled to the struct's current shape. No existing crate-wide
/// expression walker covers this, so this is a small, scope-specific `Visit`
/// impl, the same approach this module's other usage-evidence signals use
/// (e.g. [`law_of_demeter_chain_hits`], [`direct_recursive_calls`]).
struct StructConstructionCollector {
    file: PathBuf,
    sites: Vec<StructConstructionSite>,
}

impl<'ast> Visit<'ast> for StructConstructionCollector {
    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        if !node.fields.is_empty()
            && let Some(segment) = node.path.segments.last()
        {
            self.sites.push(StructConstructionSite {
                type_name: segment.ident.to_string(),
                line: node.span().start().line,
                location: EvidenceLocation {
                    file: self.file.clone(),
                    item_path: None,
                },
            });
        }
        syn::visit::visit_expr_struct(self, node);
    }
}

/// API Evolvability (todo.md §16.7's table): a `pub struct` with all-public
/// fields and no `#[non_exhaustive]` attribute is fragile to future
/// evolution — adding a field later breaks every existing struct-literal
/// construction site, forcing either a semver-major bump or a retrofitted
/// `#[non_exhaustive]`.
///
/// This is deliberately narrower, and independently corroborated, compared
/// to `api_surface`'s `semver-hazard` rule (`missing_non_exhaustive_struct_
/// fields`): that Deep-Tier finding fires on the static shape fact alone —
/// any `pub struct` with at least one `pub` field (mixed visibility
/// included) and no `#[non_exhaustive]`. This heuristic requires strictly
/// more: *all* fields public (not just one), at least
/// [`API_EVOLVABILITY_MIN_FIELDS`] of them, *and* a second, independent
/// signal — proof the crate already constructs the struct via field-literal
/// syntax, not just a hypothetical future risk.
///
/// Two independent signals, both required for the same struct:
///
/// 1. **Structural (AST)** — a `pub struct` with [`API_EVOLVABILITY_MIN_
///    FIELDS`] or more fields, all `pub`, and no `#[non_exhaustive]`
///    attribute ([`EvolvableStructCollector`]).
/// 2. **Usage-based (independent, crate-wide)** — at least one struct-
///    literal construction expression elsewhere in the same crate names
///    this struct's type and supplies at least one explicit field
///    ([`StructConstructionCollector`]). This is qualitatively different
///    from signal 1: it is empirical evidence that a caller already depends
///    on the exact field set, not a reading of the struct's own
///    declaration.
///
/// Struct names are matched to construction sites purely by last path
/// segment, not full path resolution — the same accepted-limitation
/// approach [`path_matches_io_prefix`] and `interface_segregation_
/// candidates` use for their own name matching. At most one heuristic per
/// struct: the first qualifying construction site found, in file-then-line
/// order.
fn api_evolvability_candidates(workspace: &Workspace) -> Vec<PrincipleHeuristic> {
    let mut heuristics = Vec::new();
    for krate in &workspace.crates {
        let mut candidates: Vec<EvolvableStructCandidate> = Vec::new();
        let mut construction_sites: Vec<StructConstructionSite> = Vec::new();

        for source in &krate.source_files {
            let Ok(text) = std::fs::read_to_string(&source.path) else {
                continue;
            };
            let Ok(ast) = syn::parse_file(&text) else {
                continue;
            };

            let mut struct_collector = EvolvableStructCollector {
                file: source.path.clone(),
                candidates: Vec::new(),
            };
            struct_collector.visit_file(&ast);
            candidates.extend(struct_collector.candidates);

            let mut construction_collector = StructConstructionCollector {
                file: source.path.clone(),
                sites: Vec::new(),
            };
            construction_collector.visit_file(&ast);
            construction_sites.extend(construction_collector.sites);
        }
        construction_sites
            .sort_by(|a, b| (&a.location.file, a.line).cmp(&(&b.location.file, b.line)));

        for candidate in &candidates {
            let Some(site) = construction_sites
                .iter()
                .find(|site| site.type_name == candidate.name)
            else {
                continue;
            };
            heuristics.push(build_api_evolvability_heuristic(krate, candidate, site));
        }
    }
    heuristics
}

fn build_api_evolvability_heuristic(
    krate: &CrateInfo,
    candidate: &EvolvableStructCandidate,
    site: &StructConstructionSite,
) -> PrincipleHeuristic {
    let scope = CodeScope {
        krate: krate.name.clone(),
        modules: vec![candidate.name.clone()],
    };

    let structural = Evidence {
        description: format!(
            "`{}` has {} all-public fields and no `#[non_exhaustive]` attribute, at or above \
             the {API_EVOLVABILITY_MIN_FIELDS}-field threshold this heuristic treats as an \
             evolvability concern.",
            candidate.name, candidate.field_count
        ),
        locations: vec![candidate.location.clone()],
    };
    let usage = Evidence {
        description: format!(
            "`{}` is constructed via field-literal syntax at {}:{} in the same crate, with at \
             least one explicit field rather than only a `..` spread — evidence a caller \
             already depends on this struct's current field set.",
            candidate.name,
            site.location.file.display(),
            site.line,
        ),
        locations: vec![site.location.clone()],
    };

    let evidence_identities = vec![
        candidate.name.clone(),
        site.location.file.display().to_string(),
        site.line.to_string(),
    ];
    let id = PrincipleHeuristicId::compute(
        DesignPrinciple::ApiEvolvability,
        &scope,
        &evidence_identities,
    );

    PrincipleHeuristic {
        id,
        principle: DesignPrinciple::ApiEvolvability,
        scope,
        evidence: vec![structural, usage],
        interpretation: format!(
            "`{}` exposes every field as `pub` with no `#[non_exhaustive]` attribute, and at \
             least one construction site elsewhere in the crate already relies on its exact \
             field set via field-literal syntax. Adding a field later would break that \
             construction site, either forcing a coordinated update or a semver-major bump for \
             any external caller doing the same.",
            candidate.name
        ),
        contraindications: vec![
            Contraindication {
                description: "A small, stable data-transfer struct that is unlikely to ever \
                    gain a field may not benefit from the added friction of \
                    `#[non_exhaustive]` or a constructor function."
                    .to_string(),
            },
            Contraindication {
                description: "If every construction site is internal to this crate (never \
                    exposed to external callers), adding a field later is a local, coordinated \
                    change rather than a semver hazard."
                    .to_string(),
            },
        ],
        missing_evidence: vec![MissingEvidence {
            description: "Whether this struct is actually part of the crate's external public \
                API (re-exported, reachable by downstream crates) or only an internal \
                implementation detail is not checked here — only that a field-literal \
                construction site exists somewhere in the same crate."
                .to_string(),
        }],
        alternatives: vec![
            DesignAlternative {
                description: "Keep the struct as-is.".to_string(),
            },
            DesignAlternative {
                description: "Add `#[non_exhaustive]` and a constructor function or builder, so \
                    a future field can be added without breaking existing field-literal \
                    construction sites."
                    .to_string(),
            },
        ],
        related_findings: Vec::new(),
    }
}

/// One `pub unsafe fn` found while scanning a file for
/// [`unsafe_containment_candidates`]'s signal 1 (a structural contrast, not
/// a threshold) and signal 2 (its own doc-attribute text).
struct PubUnsafeFnSite {
    qualified_name: String,
    location: EvidenceLocation,
    line: usize,
    has_safety_doc_section: bool,
}

/// One function elsewhere in the same file whose body already wraps an
/// `unsafe { .. }` block in an adjacent `// SAFETY:` comment —
/// [`unsafe_containment_candidates`]'s signal 1 contrast evidence: proof the
/// module already knows how to write a documented, encapsulated internal
/// wrapper.
struct SafetyWrapperSite {
    qualified_name: String,
    location: EvidenceLocation,
    line: usize,
}

/// Whether any comment in `comments` containing the literal substring
/// `SAFETY:` sits immediately adjacent to an unsafe block starting at
/// `unsafe_start_line` — the exact adjacency rule `crate::security`'s
/// `unsafe-surface` rule uses for its own private `has_adjacent_safety_
/// comment` helper. Duplicated here rather than imported: that helper is
/// private to `security.rs`, and this module must not modify `security.rs`
/// (see [`unsafe_containment_candidates`]'s doc comment for why this
/// detector is independent of `unsafe-surface`/`unsafe-density` in the first
/// place).
fn has_adjacent_safety_comment(comments: &[CommentSpan], unsafe_start_line: usize) -> bool {
    comments.iter().any(|comment| {
        comment.text.contains("SAFETY:")
            && (comment.end_line + 1 == unsafe_start_line
                || comment.start_line == unsafe_start_line
                || comment.start_line == unsafe_start_line + 1)
    })
}

/// Finds the first `unsafe { .. }` block in a visited body with an adjacent
/// `// SAFETY:` comment ([`has_adjacent_safety_comment`]), used by
/// [`unsafe_containment_file_sites`] to recognize a [`SafetyWrapperSite`].
/// Stops recording after the first match but keeps descending, the same
/// "small, scope-specific `Visit` impl" approach this module already uses
/// elsewhere (e.g. `EvolvableStructCollector`, `StructConstructionCollector`).
struct SafetyCommentedUnsafeBlockFinder<'a> {
    comments: &'a [CommentSpan],
    first_line: Option<usize>,
}

impl<'ast> Visit<'ast> for SafetyCommentedUnsafeBlockFinder<'_> {
    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        if self.first_line.is_none() {
            let start_line = node.span().start().line;
            if has_adjacent_safety_comment(self.comments, start_line) {
                self.first_line = Some(start_line);
            }
        }
        syn::visit::visit_expr_unsafe(self, node);
    }
}

/// Whether `attrs` contains a `#[doc = "..."]` attribute (covering both
/// `///` doc comments and an explicit `#[doc]` attribute, which `syn`
/// desugars the same way) whose joined text contains a `# Safety` rustdoc
/// heading — the standard convention for documenting an `unsafe fn`'s
/// caller-side invariants. Reuses the same `Meta::NameValue`/`Lit::Str`
/// doc-attribute extraction idiom `crate::api_surface`'s `undocumented-
/// public-item` rule (`has_doc_comment`) and `crate::slop`'s
/// `doc_comment_text` already use, duplicated locally since both are
/// private to their own modules.
fn has_safety_doc_section(attrs: &[syn::Attribute]) -> bool {
    let joined: Vec<String> = attrs
        .iter()
        .filter(|attr| attr.path().is_ident("doc"))
        .filter_map(|attr| match &attr.meta {
            syn::Meta::NameValue(name_value) => match &name_value.value {
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(text),
                    ..
                }) => Some(text.value()),
                _ => None,
            },
            _ => None,
        })
        .collect();
    joined.join(" ").contains("# Safety")
}

/// Scans one already-parsed file for [`unsafe_containment_candidates`]'s two
/// site kinds: every `pub unsafe fn` ([`PubUnsafeFnSite`]) and every other
/// function whose body already wraps an unsafe block in a `// SAFETY:`
/// comment ([`SafetyWrapperSite`]). A `pub unsafe fn` is never itself
/// counted as a safety wrapper (returns early), so a candidate can never
/// corroborate itself.
fn unsafe_containment_file_sites(
    file: &Path,
    ast: &syn::File,
    comments: &[CommentSpan],
) -> (Vec<PubUnsafeFnSite>, Vec<SafetyWrapperSite>) {
    let mut pub_unsafe_fns = Vec::new();
    let mut safety_wrappers = Vec::new();
    walk_functions(ast, |site| {
        if matches!(site.vis, Some(syn::Visibility::Public(_))) && site.sig.unsafety.is_some() {
            pub_unsafe_fns.push(PubUnsafeFnSite {
                qualified_name: site.qualified_name.clone(),
                location: EvidenceLocation {
                    file: file.to_path_buf(),
                    item_path: Some(site.qualified_name.clone()),
                },
                line: site.span.start().line,
                has_safety_doc_section: has_safety_doc_section(site.attrs),
            });
            return;
        }
        let mut finder = SafetyCommentedUnsafeBlockFinder {
            comments,
            first_line: None,
        };
        finder.visit_block(site.block);
        if let Some(line) = finder.first_line {
            safety_wrappers.push(SafetyWrapperSite {
                qualified_name: site.qualified_name.clone(),
                location: EvidenceLocation {
                    file: file.to_path_buf(),
                    item_path: Some(site.qualified_name.clone()),
                },
                line,
            });
        }
    });
    (pub_unsafe_fns, safety_wrappers)
}

/// Unsafe Containment (todo.md §16.7's table): "unsafe an vielen Stellen
/// verstreut statt gekapselt" → "Unsafe hinter enger, geprüfter Schnittstelle
/// bündeln".
///
/// This is a containment/encapsulation question, not a presence/density
/// question, and is deliberately independent of two existing `Finding`
/// rules in `crate::security`:
///
/// - `unsafe-surface` flags one `unsafe { .. }` expression block, per site,
///   missing an adjacent `// SAFETY:` comment — a documentation-completeness
///   fact about a single block.
/// - `unsafe-density` aggregates every `unsafe { .. }` block in a file into
///   how much of the file, and how large its single biggest block, is
///   unsafe — a whole-file volume/size fact.
///
/// Neither asks whether unsafe code is *encapsulated*. A file can pass both
/// existing rules — every block `SAFETY:`-commented, density and max block
/// size both low — while still exposing a raw `pub unsafe fn` that pushes
/// the safety burden onto every external caller instead of the crate
/// upholding it internally behind a narrow, safe wrapper. That is the
/// question this heuristic asks instead.
///
/// Two independent signals, both required on the same `pub unsafe fn`:
///
/// 1. **Structural contrast (AST)** — the function is itself `pub unsafe
///    fn` (definitionally not contained: the crate is telling the *caller*
///    to uphold safety invariants, rather than upholding them itself), found
///    in a file that *also* contains at least one other function (any
///    visibility) whose body wraps an `unsafe { .. }` block in an adjacent
///    `// SAFETY:` comment ([`SafetyCommentedUnsafeBlockFinder`], reusing
///    the same source-text comment scan `crate::security`'s `unsafe-surface`
///    rule uses via [`crate::slop_text::extract_comments`]). That contrast —
///    the module already has the discipline to write a documented internal
///    wrapper, yet exposes this capability raw instead — is the containment
///    failure signal, not a bare threshold.
/// 2. **Doc-attribute (independent, corroborating)** — the `pub unsafe
///    fn`'s own doc comment contains no `# Safety` rustdoc heading
///    ([`has_safety_doc_section`]). Not only is the burden pushed onto the
///    caller (signal 1), the caller is not even told what invariant to
///    uphold.
///
/// Scoped per source file (this module's "module" unit, the same file-level
/// scope [`cohesion_candidates`] uses): the contrast in signal 1 is about
/// what *this* file already demonstrates it knows how to do, not the crate
/// as a whole. At most one heuristic per qualifying `pub unsafe fn`,
/// corroborated by the first safety-commented wrapper function found in the
/// same file.
fn unsafe_containment_candidates(workspace: &Workspace) -> Vec<PrincipleHeuristic> {
    let mut heuristics = Vec::new();
    for krate in &workspace.crates {
        for source in &krate.source_files {
            let Ok(text) = std::fs::read_to_string(&source.path) else {
                continue;
            };
            let Ok(ast) = syn::parse_file(&text) else {
                continue;
            };
            let comments = extract_comments(&text);
            let (pub_unsafe_fns, safety_wrappers) =
                unsafe_containment_file_sites(&source.path, &ast, &comments);
            if safety_wrappers.is_empty() {
                continue;
            }
            for candidate in &pub_unsafe_fns {
                if candidate.has_safety_doc_section {
                    continue;
                }
                let Some(wrapper) = safety_wrappers.first() else {
                    continue;
                };
                heuristics.push(build_unsafe_containment_heuristic(
                    krate,
                    &source.path,
                    candidate,
                    wrapper,
                ));
            }
        }
    }
    heuristics
}

fn build_unsafe_containment_heuristic(
    krate: &CrateInfo,
    file: &Path,
    candidate: &PubUnsafeFnSite,
    wrapper: &SafetyWrapperSite,
) -> PrincipleHeuristic {
    let scope = CodeScope {
        krate: krate.name.clone(),
        modules: vec![candidate.qualified_name.clone()],
    };

    let structural = Evidence {
        description: format!(
            "`{}` is declared `pub unsafe fn` at {}:{}, pushing its safety invariants onto \
             every external caller instead of the crate upholding them internally behind a safe \
             wrapper.",
            candidate.qualified_name,
            file.display(),
            candidate.line,
        ),
        locations: vec![candidate.location.clone()],
    };
    let contrast = Evidence {
        description: format!(
            "The same file already wraps an `unsafe {{ .. }}` block in a `// SAFETY:` comment \
             inside `{}` at {}:{} — the module demonstrably knows how to encapsulate unsafe code \
             behind a documented internal wrapper, yet `{}` exposes raw unsafe capability \
             instead.",
            wrapper.qualified_name,
            file.display(),
            wrapper.line,
            candidate.qualified_name,
        ),
        locations: vec![wrapper.location.clone()],
    };

    let evidence_identities = vec![
        candidate.qualified_name.clone(),
        candidate.line.to_string(),
        wrapper.qualified_name.clone(),
        wrapper.line.to_string(),
    ];
    let id = PrincipleHeuristicId::compute(
        DesignPrinciple::UnsafeContainment,
        &scope,
        &evidence_identities,
    );

    PrincipleHeuristic {
        id,
        principle: DesignPrinciple::UnsafeContainment,
        scope,
        evidence: vec![structural, contrast],
        interpretation: format!(
            "`{}` is `pub unsafe fn` with no `# Safety` section in its own doc comment, so \
             callers are asked to uphold invariants that are never written down — while the \
             same file already shows, in `{}`, that the module can encapsulate unsafe code \
             behind a `// SAFETY:`-documented internal wrapper instead of exposing it at the \
             public boundary.",
            candidate.qualified_name, wrapper.qualified_name,
        ),
        contraindications: vec![
            Contraindication {
                description: "A low-level primitive whose whole purpose is to expose an unsafe \
                    capability (an FFI binding, a `no_std` allocator entry point, a SIMD \
                    intrinsic wrapper) may have no safe encapsulation to offer — the caller \
                    genuinely must uphold the invariant themselves."
                    .to_string(),
            },
            Contraindication {
                description: "If every caller of this function is internal to the crate (never \
                    part of its external public API), the party upholding the invariant may \
                    already be the same team that wrote it, with the invariant understood out of \
                    band rather than documented in rustdoc."
                    .to_string(),
            },
        ],
        missing_evidence: vec![MissingEvidence {
            description: "Whether the safety invariant is documented somewhere other than a `# \
                Safety` doc-comment section (a module-level doc, an external design doc, a plain \
                code comment above the declaration) is not checked here — only the `pub unsafe \
                fn`'s own doc attribute."
                .to_string(),
        }],
        alternatives: vec![
            DesignAlternative {
                description: "Keep the function `pub unsafe fn` as-is.".to_string(),
            },
            DesignAlternative {
                description: "Wrap the unsafe capability behind a safe `pub fn` that upholds the \
                    invariant internally, the way the file's existing `// SAFETY:`-commented \
                    wrapper already does elsewhere, or add a `# Safety` section documenting \
                    exactly what the caller must guarantee."
                    .to_string(),
            },
        ],
        related_findings: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn analyze(workspace: &Workspace) -> Vec<PrincipleHeuristic> {
        analyze_with_boundary_config(workspace, None)
    }

    fn analyze_with_boundary_config(
        workspace: &Workspace,
        boundary_config: Option<&BoundaryConfig>,
    ) -> Vec<PrincipleHeuristic> {
        let source_files = workspace
            .crates
            .iter()
            .flat_map(|krate| krate.source_files.iter());
        let complexity = crate::complexity::analyze_workspace(source_files, false);
        analyze_workspace(workspace, &complexity, boundary_config).unwrap()
    }

    /// Nine sequential `if` statements plus the base of 1 reaches exactly
    /// [`FUNCTIONAL_CORE_COMPLEXITY_THRESHOLD`] (10).
    const NINE_IFS: &str = "
    if total > 0 { total += 1; }
    if total > 1 { total += 1; }
    if total > 2 { total += 1; }
    if total > 3 { total += 1; }
    if total > 4 { total += 1; }
    if total > 5 { total += 1; }
    if total > 6 { total += 1; }
    if total > 7 { total += 1; }
    if total > 8 { total += 1; }
";

    /// (a) A function with an I/O call and complexity at/above the threshold
    /// ⇒ exactly one `PrincipleHeuristic`, with both evidence slots
    /// populated.
    #[test]
    fn io_call_plus_high_complexity_produces_one_heuristic() {
        let dir = TempDir::new("principle-io-plus-complexity");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            format!(
                "pub fn read_and_branch(path: &str) -> i32 {{\n\
                 let contents = std::fs::read_to_string(path).unwrap();\n\
                 let mut total = contents.len() as i32;\n\
                 {NINE_IFS}\n\
                 total\n\
                 }}\n"
            ),
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);

        assert_eq!(heuristics.len(), 1);
        let heuristic = &heuristics[0];
        assert_eq!(
            heuristic.principle,
            DesignPrinciple::FunctionalCoreImperativeShell
        );
        assert_eq!(heuristic.scope.krate, "fixture");
        assert_eq!(heuristic.evidence.len(), 2);
        assert!(!heuristic.evidence[0].locations.is_empty());
        assert!(!heuristic.evidence[1].locations.is_empty());
        assert!(heuristic.contraindications.len() >= 2);
        assert!(heuristic.alternatives.len() >= 2);
        assert!(!heuristic.missing_evidence.is_empty());
    }

    /// (b) An I/O call but low complexity ⇒ no heuristic.
    #[test]
    fn io_call_with_low_complexity_produces_no_heuristic() {
        let dir = TempDir::new("principle-io-low-complexity");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub fn read_simple(path: &str) -> String {\n\
             std::fs::read_to_string(path).unwrap()\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        assert!(analyze(&workspace).is_empty());
    }

    /// (c) High complexity but no I/O call ⇒ no heuristic.
    #[test]
    fn high_complexity_without_io_call_produces_no_heuristic() {
        let dir = TempDir::new("principle-complexity-no-io");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            format!(
                "pub fn branch_only(mut total: i32) -> i32 {{\n\
                 {NINE_IFS}\n\
                 total\n\
                 }}\n"
            ),
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        assert!(analyze(&workspace).is_empty());
    }

    /// A trait with [`INTERFACE_SEGREGATION_METHOD_THRESHOLD`] methods, all
    /// default-implemented so implementors may override any subset.
    const WIDE_TRAIT: &str = "
    pub trait Wide {
        fn a(&self) { let _ = 1; }
        fn b(&self) { let _ = 1; }
        fn c(&self) { let _ = 1; }
        fn d(&self) { let _ = 1; }
        fn e(&self) { let _ = 1; }
    }
";

    /// (a) A trait with >= threshold methods, plus two impls whose
    /// overridden-method sets are disjoint ⇒ exactly one `PrincipleHeuristic`
    /// for `InterfaceSegregation`, with both evidence slots populated.
    #[test]
    fn wide_trait_with_disjoint_impls_produces_one_heuristic() {
        let dir = TempDir::new("principle-interface-segregation-disjoint");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            format!(
                "{WIDE_TRAIT}\n\
                 pub struct Left;\n\
                 impl Wide for Left {{\n\
                 \x20   fn a(&self) {{}}\n\
                 \x20   fn b(&self) {{}}\n\
                 }}\n\
                 pub struct Right;\n\
                 impl Wide for Right {{\n\
                 \x20   fn c(&self) {{}}\n\
                 \x20   fn d(&self) {{}}\n\
                 }}\n"
            ),
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);

        assert_eq!(heuristics.len(), 1);
        let heuristic = &heuristics[0];
        assert_eq!(heuristic.principle, DesignPrinciple::InterfaceSegregation);
        assert_eq!(heuristic.scope.krate, "fixture");
        assert_eq!(heuristic.evidence.len(), 2);
        assert!(!heuristic.evidence[0].locations.is_empty());
        assert!(!heuristic.evidence[1].locations.is_empty());
        assert!(heuristic.contraindications.len() >= 2);
        assert!(heuristic.alternatives.len() >= 2);
        assert!(!heuristic.missing_evidence.is_empty());
    }

    /// (b) A wide trait with only one impl ⇒ no heuristic (no pair to
    /// compare).
    #[test]
    fn wide_trait_with_single_impl_produces_no_heuristic() {
        let dir = TempDir::new("principle-interface-segregation-single-impl");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            format!(
                "{WIDE_TRAIT}\n\
                 pub struct Left;\n\
                 impl Wide for Left {{\n\
                 \x20   fn a(&self) {{}}\n\
                 \x20   fn b(&self) {{}}\n\
                 }}\n"
            ),
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        assert!(analyze(&workspace).is_empty());
    }

    /// (b) A wide trait with two impls whose overridden-method sets overlap
    /// ⇒ no heuristic (no disjoint pair).
    #[test]
    fn wide_trait_with_overlapping_impls_produces_no_heuristic() {
        let dir = TempDir::new("principle-interface-segregation-overlap");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            format!(
                "{WIDE_TRAIT}\n\
                 pub struct Left;\n\
                 impl Wide for Left {{\n\
                 \x20   fn a(&self) {{}}\n\
                 \x20   fn b(&self) {{}}\n\
                 }}\n\
                 pub struct Right;\n\
                 impl Wide for Right {{\n\
                 \x20   fn b(&self) {{}}\n\
                 \x20   fn c(&self) {{}}\n\
                 }}\n"
            ),
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        assert!(analyze(&workspace).is_empty());
    }

    /// (c) A trait below the method threshold, even with disjoint impls ⇒
    /// no heuristic.
    #[test]
    fn narrow_trait_with_disjoint_impls_produces_no_heuristic() {
        let dir = TempDir::new("principle-interface-segregation-narrow");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub trait Narrow {\n\
             \x20   fn a(&self) { let _ = 1; }\n\
             \x20   fn b(&self) { let _ = 1; }\n\
             \x20   fn c(&self) { let _ = 1; }\n\
             \x20   fn d(&self) { let _ = 1; }\n\
             }\n\
             pub struct Left;\n\
             impl Narrow for Left {\n\
             \x20   fn a(&self) {}\n\
             }\n\
             pub struct Right;\n\
             impl Narrow for Right {\n\
             \x20   fn b(&self) {}\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        assert!(analyze(&workspace).is_empty());
    }

    /// (d) Both rules run over the same workspace and can report candidates
    /// at once: a `functional-core-imperative-shell` candidate in one file
    /// and an `interface-segregation` candidate in another. Mirrors what
    /// `cargo judge principles` aggregates (`judge::principle::analyze_workspace`
    /// is exactly what that command calls).
    #[test]
    fn both_rules_can_report_candidates_in_the_same_workspace() {
        let dir = TempDir::new("principle-both-rules-together");
        let io_file = dir.join("shell.rs");
        std::fs::write(
            &io_file,
            format!(
                "pub fn read_and_branch(path: &str) -> i32 {{\n\
                 let contents = std::fs::read_to_string(path).unwrap();\n\
                 let mut total = contents.len() as i32;\n\
                 {NINE_IFS}\n\
                 total\n\
                 }}\n"
            ),
        )
        .unwrap();
        let trait_file = dir.join("wide.rs");
        std::fs::write(
            &trait_file,
            format!(
                "{WIDE_TRAIT}\n\
                 pub struct Left;\n\
                 impl Wide for Left {{\n\
                 \x20   fn a(&self) {{}}\n\
                 \x20   fn b(&self) {{}}\n\
                 }}\n\
                 pub struct Right;\n\
                 impl Wide for Right {{\n\
                 \x20   fn c(&self) {{}}\n\
                 \x20   fn d(&self) {{}}\n\
                 }}\n"
            ),
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![io_file, trait_file]);
        let heuristics = analyze(&workspace);

        let principles: Vec<DesignPrinciple> = heuristics.iter().map(|h| h.principle).collect();
        assert!(principles.contains(&DesignPrinciple::FunctionalCoreImperativeShell));
        assert!(principles.contains(&DesignPrinciple::InterfaceSegregation));
        assert_eq!(heuristics.len(), 2);
    }

    /// (d) Golden wording test (todo.md §16.7 "Umsetzung und Akzeptanz"):
    /// none of the generated `interpretation`/evidence texts may contain an
    /// absolute claim of violation.
    #[test]
    fn generated_wording_never_claims_a_violation() {
        const FORBIDDEN: &[&str] = &[
            "verletzt",
            "muss",
            "falsch aufgebaut",
            "violates",
            "must",
            "is broken",
            "best practice not followed",
            "is bad",
        ];

        let dir = TempDir::new("principle-golden-wording");
        std::fs::create_dir_all(dir.join("fixture/src/domain")).unwrap();
        std::fs::write(
            dir.join("fixture/Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("fixture/src/lib.rs"),
            "pub mod domain;\npub mod infra;\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("fixture/src/shell.rs"),
            format!(
                "pub fn read_and_branch(path: &str) -> i32 {{\n\
                 let contents = std::fs::read_to_string(path).unwrap();\n\
                 let mut total = contents.len() as i32;\n\
                 {NINE_IFS}\n\
                 total\n\
                 }}\n"
            ),
        )
        .unwrap();
        std::fs::write(
            dir.join("fixture/src/wide.rs"),
            format!(
                "{WIDE_TRAIT}\n\
                 pub struct Left;\n\
                 impl Wide for Left {{\n\
                 \x20   fn a(&self) {{}}\n\
                 \x20   fn b(&self) {{}}\n\
                 }}\n\
                 pub struct Right;\n\
                 impl Wide for Right {{\n\
                 \x20   fn c(&self) {{}}\n\
                 \x20   fn d(&self) {{}}\n\
                 }}\n"
            ),
        )
        .unwrap();
        std::fs::write(
            dir.join("fixture/src/domain/mod.rs"),
            "pub fn run() {\n    crate::infra::read_file();\n}\n\n\
             pub fn build() -> crate::infra::Client {\n    todo!()\n}\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("fixture/src/infra.rs"),
            "pub fn read_file() {}\npub struct Client;\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("fixture/src/cohesion.rs"),
            format!(
                "pub fn read_config(path: &str) -> String {{\n\
                 \x20   std::fs::read_to_string(path).unwrap()\n\
                 }}\n\
                 pub fn compute(mut total: i32) -> i32 {{\n\
                 {NINE_IFS}\n\
                 \x20   total\n\
                 }}\n\
                 pub struct Marker;\n"
            ),
        )
        .unwrap();
        std::fs::write(
            dir.join("Cargo.toml"),
            "[workspace]\nmembers = [\"fixture\"]\nresolver = \"2\"\n",
        )
        .unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let config = BoundaryConfig {
            module_boundaries: vec![module_boundary_rule(
                "domain-no-infra",
                "fixture",
                "domain",
                &["infra"],
            )],
            ..Default::default()
        };
        let heuristics = analyze_with_boundary_config(&workspace, Some(&config));
        assert!(
            !heuristics.is_empty(),
            "fixture must produce a heuristic to check"
        );
        let principles: Vec<DesignPrinciple> = heuristics.iter().map(|h| h.principle).collect();
        assert!(
            principles.contains(&DesignPrinciple::FunctionalCoreImperativeShell)
                && principles.contains(&DesignPrinciple::InterfaceSegregation)
                && principles.contains(&DesignPrinciple::DependencyInversion)
                && principles.contains(&DesignPrinciple::Cohesion),
            "fixture must exercise all four rules' wording: {principles:?}"
        );

        for heuristic in &heuristics {
            let mut texts = vec![heuristic.interpretation.clone()];
            texts.extend(heuristic.evidence.iter().map(|e| e.description.clone()));
            texts.extend(
                heuristic
                    .contraindications
                    .iter()
                    .map(|c| c.description.clone()),
            );
            texts.extend(
                heuristic
                    .missing_evidence
                    .iter()
                    .map(|m| m.description.clone()),
            );
            texts.extend(heuristic.alternatives.iter().map(|a| a.description.clone()));

            for text in texts {
                let lower = text.to_lowercase();
                for forbidden in FORBIDDEN {
                    assert!(
                        !lower.contains(forbidden),
                        "forbidden wording {forbidden:?} found in {text:?}"
                    );
                }
            }
        }
    }

    // --- DependencyInversion ---------------------------------------------

    fn module_boundary_rule(
        name: &str,
        krate: &str,
        from: &str,
        forbidden: &[&str],
    ) -> ModuleBoundaryRule {
        ModuleBoundaryRule {
            name: name.to_string(),
            krate: krate.to_string(),
            from: from.to_string(),
            forbidden: forbidden.iter().map(|s| s.to_string()).collect(),
            reach: None,
        }
    }

    /// A single-crate workspace named `fixture`, with `domain`/`infra`
    /// modules (plus an optional `other` module) whose bodies are supplied
    /// by the caller — mirrors `boundaries.rs`'s own `write_crate`/
    /// `write_workspace_manifest` test fixtures, since `dependency_inversion_candidates`
    /// goes through `boundaries::evaluate`, which needs a real `cargo
    /// metadata`-readable workspace.
    fn dependency_inversion_workspace(
        dir: &TempDir,
        domain_body: &str,
        infra_body: &str,
        other_body: Option<&str>,
    ) -> Workspace {
        std::fs::create_dir_all(dir.join("fixture/src/domain")).unwrap();
        std::fs::write(
            dir.join("fixture/Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        let mut lib_rs = "pub mod domain;\npub mod infra;\n".to_string();
        if other_body.is_some() {
            lib_rs.push_str("pub mod other;\n");
        }
        std::fs::write(dir.join("fixture/src/lib.rs"), lib_rs).unwrap();
        std::fs::write(dir.join("fixture/src/domain/mod.rs"), domain_body).unwrap();
        std::fs::write(dir.join("fixture/src/infra.rs"), infra_body).unwrap();
        if let Some(other_body) = other_body {
            std::fs::write(dir.join("fixture/src/other.rs"), other_body).unwrap();
        }
        std::fs::write(
            dir.join("Cargo.toml"),
            "[workspace]\nmembers = [\"fixture\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap()
    }

    fn dependency_inversion_heuristics(
        heuristics: &[PrincipleHeuristic],
    ) -> Vec<&PrincipleHeuristic> {
        heuristics
            .iter()
            .filter(|h| h.principle == DesignPrinciple::DependencyInversion)
            .collect()
    }

    /// (a) `domain` both calls into `infra` (call-level violation) and has a
    /// `pub fn` whose return type leaks a `crate::infra` type ⇒ exactly one
    /// `DependencyInversion` heuristic, with `related_findings` populated
    /// from the corroborating `module-boundary-violation` finding(s).
    #[test]
    fn call_violation_plus_signature_leak_produces_one_heuristic() {
        let dir = TempDir::new("principle-dependency-inversion-both-signals");
        let workspace = dependency_inversion_workspace(
            &dir,
            "pub fn run() {\n    crate::infra::read_file();\n}\n\n\
             pub fn build() -> crate::infra::Client {\n    todo!()\n}\n",
            "pub fn read_file() {}\npub struct Client;\n",
            None,
        );
        let config = BoundaryConfig {
            module_boundaries: vec![module_boundary_rule(
                "domain-no-infra",
                "fixture",
                "domain",
                &["infra"],
            )],
            ..Default::default()
        };

        let heuristics = analyze_with_boundary_config(&workspace, Some(&config));
        let dependency_inversion = dependency_inversion_heuristics(&heuristics);

        assert_eq!(dependency_inversion.len(), 1);
        let heuristic = dependency_inversion[0];
        assert_eq!(heuristic.scope.krate, "fixture");
        assert_eq!(heuristic.evidence.len(), 2);
        assert!(!heuristic.evidence[0].locations.is_empty());
        assert!(!heuristic.evidence[1].locations.is_empty());
        assert!(!heuristic.related_findings.is_empty());
        assert!(heuristic.contraindications.len() >= 2);
        assert!(heuristic.alternatives.len() >= 2);
        assert!(!heuristic.missing_evidence.is_empty());
    }

    /// (b) `domain` calls into `infra` (call-level violation) but has no
    /// `pub fn` leaking an `infra` type in its signature ⇒ no
    /// `DependencyInversion` heuristic.
    #[test]
    fn call_violation_without_signature_leak_produces_no_heuristic() {
        let dir = TempDir::new("principle-dependency-inversion-call-only");
        let workspace = dependency_inversion_workspace(
            &dir,
            "pub fn run() {\n    crate::infra::read_file();\n}\n",
            "pub fn read_file() {}\npub struct Client;\n",
            None,
        );
        let config = BoundaryConfig {
            module_boundaries: vec![module_boundary_rule(
                "domain-no-infra",
                "fixture",
                "domain",
                &["infra"],
            )],
            ..Default::default()
        };

        let heuristics = analyze_with_boundary_config(&workspace, Some(&config));
        assert!(dependency_inversion_heuristics(&heuristics).is_empty());
    }

    /// (c) A `pub fn` genuinely leaks a `crate::infra` type in its return
    /// type, but it lives in an `other` module the configured
    /// `[[module_boundary]]` rule doesn't cover (`from = "domain"`) — so
    /// neither `boundaries::evaluate` nor this rule's own signature scan
    /// (both scoped to `from`) ever look at it. No `module-boundary-
    /// violation` finding exists for this rule either ⇒ no heuristic (not
    /// applicable, not a guess about `other`'s intent).
    #[test]
    fn signature_leak_outside_the_configured_module_boundary_produces_no_heuristic() {
        let dir = TempDir::new("principle-dependency-inversion-out-of-scope");
        let workspace = dependency_inversion_workspace(
            &dir,
            "pub fn run() -> i32 {\n    42\n}\n",
            "pub fn read_file() {}\npub struct Client;\n",
            Some("pub fn leaked() -> crate::infra::Client {\n    todo!()\n}\n"),
        );
        let config = BoundaryConfig {
            module_boundaries: vec![module_boundary_rule(
                "domain-no-infra",
                "fixture",
                "domain",
                &["infra"],
            )],
            ..Default::default()
        };

        let heuristics = analyze_with_boundary_config(&workspace, Some(&config));
        assert!(dependency_inversion_heuristics(&heuristics).is_empty());
    }

    /// (d) No `[[module_boundary]]` configured at all — even with both
    /// signals present in the source, the rule runs empty rather than
    /// guessing a boundary the user never configured (todo.md §17). No
    /// crash either.
    #[test]
    fn no_module_boundary_config_produces_no_heuristic() {
        let dir = TempDir::new("principle-dependency-inversion-no-config");
        let workspace = dependency_inversion_workspace(
            &dir,
            "pub fn run() {\n    crate::infra::read_file();\n}\n\n\
             pub fn build() -> crate::infra::Client {\n    todo!()\n}\n",
            "pub fn read_file() {}\npub struct Client;\n",
            None,
        );

        let heuristics = analyze_with_boundary_config(&workspace, None);
        assert!(dependency_inversion_heuristics(&heuristics).is_empty());

        let empty_config = BoundaryConfig::default();
        let heuristics = analyze_with_boundary_config(&workspace, Some(&empty_config));
        assert!(dependency_inversion_heuristics(&heuristics).is_empty());
    }

    // --- Cohesion -----------------------------------------------------------

    fn cohesion_heuristics(heuristics: &[PrincipleHeuristic]) -> Vec<&PrincipleHeuristic> {
        heuristics
            .iter()
            .filter(|h| h.principle == DesignPrinciple::Cohesion)
            .collect()
    }

    /// (a) A file with >= [`COHESION_ITEM_THRESHOLD`] public items, where one
    /// item shows `IoOperations` and a *different* item shows
    /// `ComplexComputation` ⇒ exactly one `Cohesion` heuristic, with both
    /// evidence slots populated.
    #[test]
    fn mixed_categories_across_items_produces_one_heuristic() {
        let dir = TempDir::new("principle-cohesion-mixed-categories");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            format!(
                "pub fn read_file(path: &str) -> String {{\n\
                 \x20   std::fs::read_to_string(path).unwrap()\n\
                 }}\n\
                 pub fn compute(mut total: i32) -> i32 {{\n\
                 {NINE_IFS}\n\
                 \x20   total\n\
                 }}\n\
                 pub struct Marker;\n"
            ),
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);
        let cohesion = cohesion_heuristics(&heuristics);

        assert_eq!(cohesion.len(), 1);
        let heuristic = cohesion[0];
        assert_eq!(heuristic.scope.krate, "fixture");
        assert_eq!(heuristic.evidence.len(), 2);
        assert!(!heuristic.evidence[0].locations.is_empty());
        assert!(!heuristic.evidence[1].locations.is_empty());
        assert!(heuristic.contraindications.len() >= 2);
        assert!(heuristic.alternatives.len() >= 2);
        assert!(!heuristic.missing_evidence.is_empty());
    }

    /// (b) A file with >= threshold public items, all showing the *same*
    /// single category (`ComplexComputation`) ⇒ no heuristic — category
    /// diversity, not just item count, is required.
    #[test]
    fn same_category_across_all_items_produces_no_heuristic() {
        let dir = TempDir::new("principle-cohesion-single-category");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            format!(
                "pub fn compute_a(mut total: i32) -> i32 {{\n{NINE_IFS}\n\x20   total\n}}\n\
                 pub fn compute_b(mut total: i32) -> i32 {{\n{NINE_IFS}\n\x20   total\n}}\n\
                 pub fn compute_c(mut total: i32) -> i32 {{\n{NINE_IFS}\n\x20   total\n}}\n"
            ),
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        assert!(analyze(&workspace).is_empty());
    }

    /// (c) Only 2 public items, even with different categories ⇒ no
    /// heuristic (item-count threshold of 3 not reached).
    #[test]
    fn below_item_threshold_produces_no_heuristic() {
        let dir = TempDir::new("principle-cohesion-below-threshold");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            format!(
                "pub fn read_file(path: &str) -> String {{\n\
                 \x20   std::fs::read_to_string(path).unwrap()\n\
                 }}\n\
                 pub fn compute(mut total: i32) -> i32 {{\n\
                 {NINE_IFS}\n\
                 \x20   total\n\
                 }}\n"
            ),
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        assert!(analyze(&workspace).is_empty());
    }

    /// (d) Abgrenzung from `functional-core-imperative-shell`: one function
    /// mixes `IoOperations` and `ComplexComputation` *itself*, and the file
    /// has enough other public items to reach the item-count threshold, but
    /// none of those other items show any effect category at all. Only one
    /// item in the whole file carries a category, so no *pair of different
    /// items* with differing categories exists ⇒ no `Cohesion` heuristic,
    /// even though `functional-core-imperative-shell` fires for that same
    /// function.
    #[test]
    fn single_item_mixing_categories_produces_no_cohesion_heuristic() {
        let dir = TempDir::new("principle-cohesion-single-item-mix");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            format!(
                "pub fn read_and_branch(path: &str) -> i32 {{\n\
                 \x20   let contents = std::fs::read_to_string(path).unwrap();\n\
                 \x20   let mut total = contents.len() as i32;\n\
                 {NINE_IFS}\n\
                 \x20   total\n\
                 }}\n\
                 pub struct Marker;\n\
                 pub struct OtherMarker;\n"
            ),
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);

        let principles: Vec<DesignPrinciple> = heuristics.iter().map(|h| h.principle).collect();
        assert!(principles.contains(&DesignPrinciple::FunctionalCoreImperativeShell));
        assert!(cohesion_heuristics(&heuristics).is_empty());
    }

    // --- Multi-crate workspace fixtures (todo.md §16.7) ---------------------
    //
    // Everything above builds a single synthetic crate (`workspace_with_crate`)
    // or, for `DependencyInversion`, a single real on-disk crate inside a
    // one-member workspace (`dependency_inversion_workspace`). The tests below
    // instead build a real on-disk `[workspace] members = [...]` with *two*
    // crates via `crate::ingest::load` (the same `cargo metadata`-backed path
    // `dependency_inversion_workspace` and `dep_graph.rs`'s own multi-crate
    // fixtures already use), to prove each rule stays crate-local: evidence
    // from one crate does not bleed into another, and an unrelated second
    // crate in the same workspace neither gets falsely flagged nor causes a
    // crash. Each rule also gets a deliberate orchestrator/facade negative
    // fixture, so structural size alone (many pub items, several sequenced
    // calls) is never mistaken for the rule's actual two-signal evidence.

    /// Writes a virtual `[workspace]` manifest listing `members` at `dir`'s
    /// `Cargo.toml` — the multi-crate counterpart of
    /// `dependency_inversion_workspace`'s single-member manifest.
    fn write_multi_crate_manifest(dir: &TempDir, members: &[&str]) {
        let members_toml = members
            .iter()
            .map(|m| format!("\"{m}\""))
            .collect::<Vec<_>>()
            .join(", ");
        std::fs::write(
            dir.join("Cargo.toml"),
            format!("[workspace]\nmembers = [{members_toml}]\nresolver = \"2\"\n"),
        )
        .unwrap();
    }

    /// Writes one workspace member crate named `name` at `dir/<name>`, with
    /// `lib_rs` as its entire `src/lib.rs` body.
    fn write_crate_member(dir: &TempDir, name: &str, lib_rs: &str) {
        std::fs::create_dir_all(dir.join(name).join("src")).unwrap();
        std::fs::write(
            dir.join(name).join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
        )
        .unwrap();
        std::fs::write(dir.join(name).join("src/lib.rs"), lib_rs).unwrap();
    }

    /// Writes one workspace member crate named `name` with a `domain`/`infra`
    /// module split — the multi-crate counterpart of
    /// `dependency_inversion_workspace`'s single-crate `fixture`.
    fn write_domain_infra_crate_member(
        dir: &TempDir,
        name: &str,
        domain_body: &str,
        infra_body: &str,
    ) {
        std::fs::create_dir_all(dir.join(name).join("src/domain")).unwrap();
        std::fs::write(
            dir.join(name).join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
        )
        .unwrap();
        std::fs::write(
            dir.join(name).join("src/lib.rs"),
            "pub mod domain;\npub mod infra;\n",
        )
        .unwrap();
        std::fs::write(dir.join(name).join("src/domain/mod.rs"), domain_body).unwrap();
        std::fs::write(dir.join(name).join("src/infra.rs"), infra_body).unwrap();
    }

    /// `FunctionalCoreImperativeShell`: `crate_a` has a function mixing both
    /// signals; `crate_b` only has pure computation. Both in the same
    /// `cargo judge principles` run ⇒ exactly one heuristic, scoped to
    /// `crate_a` — not zero (crate_a's evidence must still be found) and not
    /// two (crate_b's unrelated pure function must not be flagged).
    #[test]
    fn functional_core_signal_is_scoped_to_the_crate_that_has_it() {
        let dir = TempDir::new("principle-fcis-multi-crate");
        write_multi_crate_manifest(&dir, &["crate_a", "crate_b"]);
        write_crate_member(
            &dir,
            "crate_a",
            &format!(
                "pub fn read_and_branch(path: &str) -> i32 {{\n\
                 \x20   let contents = std::fs::read_to_string(path).unwrap();\n\
                 \x20   let mut total = contents.len() as i32;\n\
                 {NINE_IFS}\n\
                 \x20   total\n\
                 }}\n"
            ),
        );
        write_crate_member(
            &dir,
            "crate_b",
            "pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n",
        );

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let heuristics = analyze(&workspace);
        let fcis: Vec<&PrincipleHeuristic> = heuristics
            .iter()
            .filter(|h| h.principle == DesignPrinciple::FunctionalCoreImperativeShell)
            .collect();

        assert_eq!(fcis.len(), 1);
        assert_eq!(fcis[0].scope.krate, "crate_a");
    }

    /// `FunctionalCoreImperativeShell` orchestrator/facade negative fixture:
    /// a function that sequences several I/O calls one after another (looks
    /// structurally busy) but has no non-trivial branching, so its cyclomatic
    /// complexity stays well below the threshold ⇒ no heuristic, even though
    /// signal 1 (I/O calls) alone is present. An unrelated second crate sits
    /// in the same workspace and stays unaffected.
    #[test]
    fn thin_orchestrator_sequencing_io_without_branching_produces_no_fcis_heuristic() {
        let dir = TempDir::new("principle-fcis-orchestrator");
        write_multi_crate_manifest(&dir, &["orchestrator", "other"]);
        write_crate_member(
            &dir,
            "orchestrator",
            "pub fn run_pipeline(path: &str) -> std::io::Result<()> {\n\
             \x20   let _a = std::fs::read_to_string(path)?;\n\
             \x20   let _b = std::fs::read_to_string(path)?;\n\
             \x20   std::fs::write(path, \"done\")?;\n\
             \x20   Ok(())\n\
             }\n",
        );
        write_crate_member(&dir, "other", "pub fn noop() {}\n");

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let heuristics = analyze(&workspace);
        assert!(
            heuristics
                .iter()
                .all(|h| h.principle != DesignPrinciple::FunctionalCoreImperativeShell)
        );
    }

    /// `InterfaceSegregation`: `crate_a` has a wide `Wide` trait with two
    /// disjoint-overriding impls; `crate_b` declares a same-named `Wide`
    /// trait that is a completely different, narrow (below-threshold) trait.
    /// Exactly one heuristic, scoped to `crate_a` — proves traits are grouped
    /// strictly per crate (`workspace.crates` is iterated one crate at a
    /// time), not matched by name across crate boundaries.
    #[test]
    fn interface_segregation_signal_is_scoped_to_the_crate_that_has_it() {
        let dir = TempDir::new("principle-interface-segregation-multi-crate");
        write_multi_crate_manifest(&dir, &["crate_a", "crate_b"]);
        write_crate_member(
            &dir,
            "crate_a",
            &format!(
                "{WIDE_TRAIT}\n\
                 pub struct Left;\n\
                 impl Wide for Left {{\n\
                 \x20   fn a(&self) {{}}\n\
                 \x20   fn b(&self) {{}}\n\
                 }}\n\
                 pub struct Right;\n\
                 impl Wide for Right {{\n\
                 \x20   fn c(&self) {{}}\n\
                 \x20   fn d(&self) {{}}\n\
                 }}\n"
            ),
        );
        write_crate_member(
            &dir,
            "crate_b",
            "pub trait Wide {\n\
             \x20   fn x(&self) { let _ = 1; }\n\
             \x20   fn y(&self) { let _ = 1; }\n\
             }\n\
             pub struct Left;\n\
             impl Wide for Left {\n\
             \x20   fn x(&self) {}\n\
             }\n\
             pub struct Right;\n\
             impl Wide for Right {\n\
             \x20   fn y(&self) {}\n\
             }\n",
        );

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let heuristics = analyze(&workspace);
        let interface_segregation: Vec<&PrincipleHeuristic> = heuristics
            .iter()
            .filter(|h| h.principle == DesignPrinciple::InterfaceSegregation)
            .collect();

        assert_eq!(interface_segregation.len(), 1);
        assert_eq!(interface_segregation[0].scope.krate, "crate_a");
    }

    /// `InterfaceSegregation` orchestrator/facade negative fixture: two
    /// deliberate full adapters, each implementing *every* method of the wide
    /// trait (not a partial/disjoint split) ⇒ no heuristic — the trait is
    /// structurally wide (signal 1), but signal 2 (a genuine disjoint usage
    /// split) never fires since the adapters' overridden sets fully overlap.
    #[test]
    fn full_adapters_implementing_the_whole_interface_produce_no_interface_segregation_heuristic() {
        let dir = TempDir::new("principle-interface-segregation-full-adapters");
        write_multi_crate_manifest(&dir, &["adapters", "other"]);
        write_crate_member(
            &dir,
            "adapters",
            &format!(
                "{WIDE_TRAIT}\n\
                 pub struct AdapterOne;\n\
                 impl Wide for AdapterOne {{\n\
                 \x20   fn a(&self) {{}}\n\
                 \x20   fn b(&self) {{}}\n\
                 \x20   fn c(&self) {{}}\n\
                 \x20   fn d(&self) {{}}\n\
                 \x20   fn e(&self) {{}}\n\
                 }}\n\
                 pub struct AdapterTwo;\n\
                 impl Wide for AdapterTwo {{\n\
                 \x20   fn a(&self) {{}}\n\
                 \x20   fn b(&self) {{}}\n\
                 \x20   fn c(&self) {{}}\n\
                 \x20   fn d(&self) {{}}\n\
                 \x20   fn e(&self) {{}}\n\
                 }}\n"
            ),
        );
        write_crate_member(&dir, "other", "pub fn noop() {}\n");

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let heuristics = analyze(&workspace);
        assert!(
            heuristics
                .iter()
                .all(|h| h.principle != DesignPrinciple::InterfaceSegregation)
        );
    }

    /// `DependencyInversion`: the `[[module_boundary]]` rule only names
    /// `crate_a` (which has both the call-level violation and the signature
    /// leak); `crate_b` is not mentioned in config at all. Exactly one
    /// heuristic, scoped to `crate_a`, and `crate_b`'s presence causes no
    /// crash despite having no config entry of its own.
    #[test]
    fn dependency_inversion_signal_is_scoped_to_the_configured_crate() {
        let dir = TempDir::new("principle-dependency-inversion-multi-crate");
        write_multi_crate_manifest(&dir, &["crate_a", "crate_b"]);
        write_domain_infra_crate_member(
            &dir,
            "crate_a",
            "pub fn run() {\n    crate::infra::read_file();\n}\n\n\
             pub fn build() -> crate::infra::Client {\n    todo!()\n}\n",
            "pub fn read_file() {}\npub struct Client;\n",
        );
        write_crate_member(
            &dir,
            "crate_b",
            "pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n",
        );

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let config = BoundaryConfig {
            module_boundaries: vec![module_boundary_rule(
                "domain-no-infra",
                "crate_a",
                "domain",
                &["infra"],
            )],
            ..Default::default()
        };

        let heuristics = analyze_with_boundary_config(&workspace, Some(&config));
        let dependency_inversion = dependency_inversion_heuristics(&heuristics);

        assert_eq!(dependency_inversion.len(), 1);
        assert_eq!(dependency_inversion[0].scope.krate, "crate_a");
    }

    /// `DependencyInversion` orchestrator/facade negative fixture: `domain`
    /// sequences calls into `infra` (a genuine call-level violation, the
    /// first signal), but its own public signatures never name an infra
    /// type — the properly abstracted orchestrator shape this heuristic is
    /// meant to leave alone, so no heuristic despite the call-level finding
    /// existing.
    #[test]
    fn orchestrator_calling_infra_without_leaking_its_types_produces_no_dependency_inversion_heuristic()
     {
        let dir = TempDir::new("principle-dependency-inversion-orchestrator");
        write_multi_crate_manifest(&dir, &["crate_a", "crate_b"]);
        write_domain_infra_crate_member(
            &dir,
            "crate_a",
            "pub fn run() -> bool {\n    \
             crate::infra::read_file();\n    \
             crate::infra::write_file();\n    \
             true\n}\n",
            "pub fn read_file() {}\npub fn write_file() {}\npub struct Client;\n",
        );
        write_crate_member(
            &dir,
            "crate_b",
            "pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n",
        );

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let config = BoundaryConfig {
            module_boundaries: vec![module_boundary_rule(
                "domain-no-infra",
                "crate_a",
                "domain",
                &["infra"],
            )],
            ..Default::default()
        };

        let heuristics = analyze_with_boundary_config(&workspace, Some(&config));
        assert!(dependency_inversion_heuristics(&heuristics).is_empty());
    }

    /// `Cohesion`: `crate_a` has a file with >= threshold public items where
    /// two different items show different effect categories; `crate_b` has a
    /// file with >= threshold public items that all show the *same* category.
    /// Exactly one heuristic, scoped to `crate_a`.
    #[test]
    fn cohesion_signal_is_scoped_to_the_crate_that_has_it() {
        let dir = TempDir::new("principle-cohesion-multi-crate");
        write_multi_crate_manifest(&dir, &["crate_a", "crate_b"]);
        write_crate_member(
            &dir,
            "crate_a",
            &format!(
                "pub fn read_file(path: &str) -> String {{\n\
                 \x20   std::fs::read_to_string(path).unwrap()\n\
                 }}\n\
                 pub fn compute(mut total: i32) -> i32 {{\n\
                 {NINE_IFS}\n\
                 \x20   total\n\
                 }}\n\
                 pub struct Marker;\n"
            ),
        );
        write_crate_member(
            &dir,
            "crate_b",
            &format!(
                "pub fn compute_a(mut total: i32) -> i32 {{\n{NINE_IFS}\n\x20   total\n}}\n\
                 pub fn compute_b(mut total: i32) -> i32 {{\n{NINE_IFS}\n\x20   total\n}}\n\
                 pub fn compute_c(mut total: i32) -> i32 {{\n{NINE_IFS}\n\x20   total\n}}\n"
            ),
        );

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let heuristics = analyze(&workspace);
        let cohesion: Vec<&PrincipleHeuristic> = heuristics
            .iter()
            .filter(|h| h.principle == DesignPrinciple::Cohesion)
            .collect();

        assert_eq!(cohesion.len(), 1);
        assert_eq!(cohesion[0].scope.krate, "crate_a");
    }

    /// `Cohesion` orchestrator/facade negative fixture: a deliberate
    /// orchestration file bundling several pre-existing steps behind public
    /// wrapper functions — enough public items to satisfy the structural
    /// signal, but none of them show any of this heuristic's effect
    /// categories (no I/O, no terminal output, no complexity at/above the
    /// threshold) ⇒ no heuristic, even though the file looks structurally
    /// big.
    #[test]
    fn orchestrator_module_bundling_delegate_calls_produces_no_cohesion_heuristic() {
        let dir = TempDir::new("principle-cohesion-orchestrator");
        write_multi_crate_manifest(&dir, &["facade", "other"]);
        write_crate_member(
            &dir,
            "facade",
            "pub fn step_one() -> i32 {\n    1\n}\n\
             pub fn step_two() -> i32 {\n    2\n}\n\
             pub fn step_three() -> i32 {\n    3\n}\n\
             pub fn run_all() -> i32 {\n    step_one() + step_two() + step_three()\n}\n",
        );
        write_crate_member(&dir, "other", "pub fn noop() {}\n");

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let heuristics = analyze(&workspace);
        assert!(
            heuristics
                .iter()
                .all(|h| h.principle != DesignPrinciple::Cohesion)
        );
    }

    /// (a) An unbroken 3-call method chain on a non-`self` base ⇒ exactly
    /// one `LawOfDemeter` heuristic, with both evidence slots populated.
    #[test]
    fn law_of_demeter_unbroken_three_call_chain_produces_one_heuristic() {
        let dir = TempDir::new("principle-demeter-chain");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub fn reach(collector: &Collector) -> i32 {\n\
             \x20   collector.repository().connection().timeout()\n\
             }\n\
             pub struct Collector;\n\
             pub struct Repository;\n\
             pub struct Connection;\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);
        let demeter: Vec<&PrincipleHeuristic> = heuristics
            .iter()
            .filter(|h| h.principle == DesignPrinciple::LawOfDemeter)
            .collect();

        assert_eq!(demeter.len(), 1);
        let heuristic = demeter[0];
        assert_eq!(heuristic.scope.krate, "fixture");
        assert_eq!(heuristic.evidence.len(), 2);
        assert!(!heuristic.evidence[0].locations.is_empty());
        assert!(!heuristic.evidence[1].locations.is_empty());
        assert!(heuristic.contraindications.len() >= 2);
        assert!(heuristic.alternatives.len() >= 2);
        assert!(!heuristic.missing_evidence.is_empty());
    }

    /// (b) The same chain, but one of its intermediate results is already
    /// bound to a sibling `let` in the same block ⇒ no heuristic (signal 1
    /// present, signal 2 absent).
    #[test]
    fn law_of_demeter_chain_with_sibling_intermediate_let_produces_no_heuristic() {
        let dir = TempDir::new("principle-demeter-chain-let");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub fn reach(collector: &Collector) -> i32 {\n\
             \x20   let _cached = collector.repository().connection();\n\
             \x20   collector.repository().connection().timeout()\n\
             }\n\
             pub struct Collector;\n\
             pub struct Repository;\n\
             pub struct Connection;\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);
        assert!(
            heuristics
                .iter()
                .all(|h| h.principle != DesignPrinciple::LawOfDemeter)
        );
    }

    /// (c) A chain starting from a one-level-deep `self.field` access ⇒ no
    /// heuristic — excluded before either signal is checked, even though
    /// the chain itself is 3 calls long and unbroken.
    #[test]
    fn law_of_demeter_chain_starting_from_self_field_produces_no_heuristic() {
        let dir = TempDir::new("principle-demeter-chain-self");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub struct Widget {\n\
             \x20   inner: Inner,\n\
             }\n\
             impl Widget {\n\
             \x20   pub fn reach(&self) -> i32 {\n\
             \x20\x20\x20   self.inner.repository().connection().timeout()\n\
             \x20   }\n\
             }\n\
             pub struct Inner;\n\
             pub struct Repository;\n\
             pub struct Connection;\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);
        assert!(
            heuristics
                .iter()
                .all(|h| h.principle != DesignPrinciple::LawOfDemeter)
        );
    }

    /// (a) A `loop { ... }` with no `break`/`return`/`?`/`panic!`/
    /// `std::process::exit` anywhere in its own body ⇒ exactly one
    /// `BoundedResources` heuristic, with both evidence slots populated.
    #[test]
    fn bounded_resources_loop_without_any_exit_produces_one_heuristic() {
        let dir = TempDir::new("principle-bounded-resources-loop");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub fn spin(counter: &mut i32) {\n\
             \x20   loop {\n\
             \x20\x20\x20   *counter += 1;\n\
             \x20   }\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);
        let bounded: Vec<&PrincipleHeuristic> = heuristics
            .iter()
            .filter(|h| h.principle == DesignPrinciple::BoundedResources)
            .collect();

        assert_eq!(bounded.len(), 1);
        let heuristic = bounded[0];
        assert_eq!(heuristic.scope.krate, "fixture");
        assert_eq!(heuristic.evidence.len(), 2);
        assert!(!heuristic.evidence[0].locations.is_empty());
        assert!(!heuristic.evidence[1].locations.is_empty());
        assert!(heuristic.contraindications.len() >= 2);
        assert!(heuristic.alternatives.len() >= 2);
        assert!(!heuristic.missing_evidence.is_empty());
    }

    /// (b) The same shape, but the loop has a `break` ⇒ no heuristic.
    #[test]
    fn bounded_resources_loop_with_break_produces_no_heuristic() {
        let dir = TempDir::new("principle-bounded-resources-loop-break");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub fn spin(counter: &mut i32) -> i32 {\n\
             \x20   loop {\n\
             \x20\x20\x20   *counter += 1;\n\
             \x20\x20\x20   if *counter > 3 {\n\
             \x20\x20\x20\x20\x20   break;\n\
             \x20\x20\x20   }\n\
             \x20   }\n\
             \x20   *counter\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);
        assert!(
            heuristics
                .iter()
                .all(|h| h.principle != DesignPrinciple::BoundedResources)
        );
    }

    /// (c) A directly self-recursive function with no parameter-referencing
    /// guard before the recursive call ⇒ exactly one `BoundedResources`
    /// heuristic, with both evidence slots populated.
    #[test]
    fn bounded_resources_direct_recursion_without_guard_produces_one_heuristic() {
        let dir = TempDir::new("principle-bounded-resources-recursion");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub fn countdown(n: i32) -> i32 {\n\
             \x20   countdown(n - 1)\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);
        let bounded: Vec<&PrincipleHeuristic> = heuristics
            .iter()
            .filter(|h| h.principle == DesignPrinciple::BoundedResources)
            .collect();

        assert_eq!(bounded.len(), 1);
        let heuristic = bounded[0];
        assert_eq!(heuristic.scope.krate, "fixture");
        assert_eq!(heuristic.evidence.len(), 2);
        assert!(!heuristic.evidence[0].locations.is_empty());
        assert!(!heuristic.evidence[1].locations.is_empty());
        assert!(heuristic.contraindications.len() >= 2);
        assert!(heuristic.alternatives.len() >= 2);
        assert!(!heuristic.missing_evidence.is_empty());
    }

    /// (d) The same shape, but a `if` on the parameter guards the recursive
    /// call with a non-recursive return path ⇒ no heuristic.
    #[test]
    fn bounded_resources_direct_recursion_with_parameter_guard_produces_no_heuristic() {
        let dir = TempDir::new("principle-bounded-resources-recursion-guard");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub fn countdown(n: i32) -> i32 {\n\
             \x20   if n <= 0 {\n\
             \x20\x20\x20   return 0;\n\
             \x20   }\n\
             \x20   countdown(n - 1)\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);
        assert!(
            heuristics
                .iter()
                .all(|h| h.principle != DesignPrinciple::BoundedResources)
        );
    }

    // --- ParseDontValidate --------------------------------------------

    /// (a) A `pub fn` with a validation-shaped guard on a `&str` parameter
    /// that still returns a `bool`, plus a private sibling function
    /// elsewhere in the crate independently guarding another `&str`
    /// parameter the same way ⇒ exactly one `ParseDontValidate` heuristic
    /// (the private sibling only corroborates signal 2, it does not itself
    /// qualify for signal 1's `pub fn` gate).
    #[test]
    fn parse_dont_validate_with_crate_wide_duplication_produces_one_heuristic() {
        let dir = TempDir::new("principle-parse-dont-validate");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub fn validate_email(s: &str) -> bool {\n\
             \x20   if s.is_empty() {\n\
             \x20\x20\x20   return false;\n\
             \x20   }\n\
             \x20   true\n\
             }\n\
             \n\
             fn check_username(u: &str) -> bool {\n\
             \x20   if u.is_empty() {\n\
             \x20\x20\x20   return false;\n\
             \x20   }\n\
             \x20   true\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);
        let parse_dont_validate: Vec<&PrincipleHeuristic> = heuristics
            .iter()
            .filter(|h| h.principle == DesignPrinciple::ParseDontValidate)
            .collect();

        assert_eq!(parse_dont_validate.len(), 1);
        let heuristic = parse_dont_validate[0];
        assert_eq!(heuristic.scope.krate, "fixture");
        assert_eq!(heuristic.evidence.len(), 2);
        assert!(!heuristic.evidence[0].locations.is_empty());
        assert!(!heuristic.evidence[1].locations.is_empty());
        assert!(heuristic.contraindications.len() >= 2);
        assert!(heuristic.alternatives.len() >= 2);
        assert!(!heuristic.missing_evidence.is_empty());
    }

    /// (b) The same target function, but with no other function in the
    /// crate guarding a parameter of the same primitive kind ⇒ no
    /// heuristic — proves signal 2 actually gates, it isn't decorative.
    #[test]
    fn parse_dont_validate_without_crate_wide_duplication_produces_no_heuristic() {
        let dir = TempDir::new("principle-parse-dont-validate-no-corroboration");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub fn validate_email(s: &str) -> bool {\n\
             \x20   if s.is_empty() {\n\
             \x20\x20\x20   return false;\n\
             \x20   }\n\
             \x20   true\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);
        assert!(
            heuristics
                .iter()
                .all(|h| h.principle != DesignPrinciple::ParseDontValidate)
        );
    }

    /// (c) A function that validates and then parses into a distinct
    /// newtype (`Result<Email, _>`) ⇒ no heuristic, even with a private
    /// sibling elsewhere guarding another `&str` parameter the same way —
    /// proves the "already parses into a distinct type" exclusion works
    /// rather than the negative result just being an absence of signal 2.
    #[test]
    fn parse_dont_validate_that_parses_into_a_newtype_produces_no_heuristic() {
        let dir = TempDir::new("principle-parse-dont-validate-newtype");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub struct Email(String);\n\
             \n\
             pub fn parse_email(s: &str) -> Result<Email, String> {\n\
             \x20   if s.is_empty() {\n\
             \x20\x20\x20   return Err(\"empty\".to_string());\n\
             \x20   }\n\
             \x20   Ok(Email(s.to_string()))\n\
             }\n\
             \n\
             fn check_username(u: &str) -> bool {\n\
             \x20   if u.is_empty() {\n\
             \x20\x20\x20   return false;\n\
             \x20   }\n\
             \x20   true\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);
        assert!(
            heuristics
                .iter()
                .all(|h| h.principle != DesignPrinciple::ParseDontValidate)
        );
    }

    /// (a) An all-public-field `pub struct` (no `#[non_exhaustive]`, at or
    /// above [`API_EVOLVABILITY_MIN_FIELDS`]) plus a field-literal
    /// construction site elsewhere in the crate ⇒ exactly one
    /// `ApiEvolvability` heuristic, with both evidence slots populated.
    #[test]
    fn api_evolvability_with_construction_site_produces_one_heuristic() {
        let dir = TempDir::new("principle-api-evolvability");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub struct Point {\n\
             \x20   pub x: i32,\n\
             \x20   pub y: i32,\n\
             }\n\
             \n\
             pub fn origin_shifted() -> Point {\n\
             \x20   Point { x: 1, y: 2 }\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);
        let api_evolvability: Vec<&PrincipleHeuristic> = heuristics
            .iter()
            .filter(|h| h.principle == DesignPrinciple::ApiEvolvability)
            .collect();

        assert_eq!(api_evolvability.len(), 1);
        let heuristic = api_evolvability[0];
        assert_eq!(heuristic.scope.krate, "fixture");
        assert_eq!(heuristic.evidence.len(), 2);
        assert!(!heuristic.evidence[0].locations.is_empty());
        assert!(!heuristic.evidence[1].locations.is_empty());
        assert!(heuristic.contraindications.len() >= 2);
        assert!(heuristic.alternatives.len() >= 2);
        assert!(!heuristic.missing_evidence.is_empty());
    }

    /// (b) The same struct shape, but no construction site anywhere in the
    /// crate (only ever built via `Default::default()`) ⇒ no heuristic —
    /// proves signal 2 actually gates the result.
    #[test]
    fn api_evolvability_without_construction_site_produces_no_heuristic() {
        let dir = TempDir::new("principle-api-evolvability-no-construction");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "#[derive(Default)]\n\
             pub struct Point {\n\
             \x20   pub x: i32,\n\
             \x20   pub y: i32,\n\
             }\n\
             \n\
             pub fn origin() -> Point {\n\
             \x20   Point { ..Default::default() }\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);
        assert!(
            heuristics
                .iter()
                .all(|h| h.principle != DesignPrinciple::ApiEvolvability)
        );
    }

    /// (c) The same struct shape, but with `#[non_exhaustive]` ⇒ no
    /// heuristic.
    #[test]
    fn api_evolvability_with_non_exhaustive_produces_no_heuristic() {
        let dir = TempDir::new("principle-api-evolvability-non-exhaustive");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "#[non_exhaustive]\n\
             pub struct Point {\n\
             \x20   pub x: i32,\n\
             \x20   pub y: i32,\n\
             }\n\
             \n\
             pub fn origin_shifted() -> Point {\n\
             \x20   Point { x: 1, y: 2 }\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);
        assert!(
            heuristics
                .iter()
                .all(|h| h.principle != DesignPrinciple::ApiEvolvability)
        );
    }

    /// (d) A struct with at least one private field (mixed visibility) ⇒ no
    /// heuristic, even with a matching field-literal construction site —
    /// proves signal 1's "fully public" requirement actually gates.
    #[test]
    fn api_evolvability_with_private_field_produces_no_heuristic() {
        let dir = TempDir::new("principle-api-evolvability-private-field");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub struct Point {\n\
             \x20   pub x: i32,\n\
             \x20   y: i32,\n\
             }\n\
             \n\
             impl Point {\n\
             \x20   pub fn shifted() -> Point {\n\
             \x20\x20\x20   Point { x: 1, y: 2 }\n\
             \x20   }\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);
        assert!(
            heuristics
                .iter()
                .all(|h| h.principle != DesignPrinciple::ApiEvolvability)
        );
    }

    /// (a) A `pub unsafe fn` with no `# Safety` doc section, in a module
    /// that also has a properly `// SAFETY:`-commented internal unsafe
    /// block elsewhere ⇒ exactly one `UnsafeContainment` heuristic, with
    /// both evidence slots populated.
    #[test]
    fn undocumented_pub_unsafe_fn_with_safety_wrapper_produces_one_heuristic() {
        let dir = TempDir::new("principle-unsafe-containment-undocumented");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub unsafe fn raw_read(ptr: *const u8) -> u8 {\n\
             \x20   unsafe { *ptr }\n\
             }\n\
             \n\
             pub fn safe_read(ptr: *const u8) -> u8 {\n\
             \x20   // SAFETY: caller guarantees ptr is valid and aligned\n\
             \x20   unsafe { *ptr }\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);
        let unsafe_containment: Vec<&PrincipleHeuristic> = heuristics
            .iter()
            .filter(|h| h.principle == DesignPrinciple::UnsafeContainment)
            .collect();

        assert_eq!(unsafe_containment.len(), 1);
        let heuristic = unsafe_containment[0];
        assert_eq!(heuristic.scope.krate, "fixture");
        assert_eq!(heuristic.evidence.len(), 2);
        assert!(!heuristic.evidence[0].locations.is_empty());
        assert!(!heuristic.evidence[1].locations.is_empty());
        assert!(heuristic.contraindications.len() >= 2);
        assert!(heuristic.alternatives.len() >= 2);
        assert!(!heuristic.missing_evidence.is_empty());
    }

    /// (b) The same shape, but the `pub unsafe fn` has a `# Safety` doc
    /// section ⇒ no heuristic — proves signal 2 gates.
    #[test]
    fn documented_pub_unsafe_fn_with_safety_wrapper_produces_no_heuristic() {
        let dir = TempDir::new("principle-unsafe-containment-documented");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "/// Reads a raw pointer.\n\
             ///\n\
             /// # Safety\n\
             ///\n\
             /// `ptr` must be valid and aligned.\n\
             pub unsafe fn raw_read(ptr: *const u8) -> u8 {\n\
             \x20   unsafe { *ptr }\n\
             }\n\
             \n\
             pub fn safe_read(ptr: *const u8) -> u8 {\n\
             \x20   // SAFETY: caller guarantees ptr is valid and aligned\n\
             \x20   unsafe { *ptr }\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);
        assert!(
            heuristics
                .iter()
                .all(|h| h.principle != DesignPrinciple::UnsafeContainment)
        );
    }

    /// (c) A `pub unsafe fn` with no `# Safety` doc section, but no other
    /// `// SAFETY:`-commented unsafe block anywhere in the module (the
    /// module never demonstrates it knows how to write a safe wrapper) ⇒ no
    /// heuristic — proves signal 1's contrast-based framing gates.
    #[test]
    fn undocumented_pub_unsafe_fn_without_safety_wrapper_produces_no_heuristic() {
        let dir = TempDir::new("principle-unsafe-containment-no-wrapper");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            "pub unsafe fn raw_read(ptr: *const u8) -> u8 {\n\
             \x20   unsafe { *ptr }\n\
             }\n",
        )
        .unwrap();

        let workspace = workspace_with_crate(dir.to_path_buf(), vec![file]);
        let heuristics = analyze(&workspace);
        assert!(
            heuristics
                .iter()
                .all(|h| h.principle != DesignPrinciple::UnsafeContainment)
        );
    }
}
