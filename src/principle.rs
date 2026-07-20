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
//! sixteen table entries), plus four real detectors —
//! [`FunctionalCoreImperativeShell`](DesignPrinciple::FunctionalCoreImperativeShell)
//! (see [`functional_core_imperative_shell_candidates`]),
//! [`InterfaceSegregation`](DesignPrinciple::InterfaceSegregation) (see
//! [`interface_segregation_candidates`]),
//! [`DependencyInversion`](DesignPrinciple::DependencyInversion) (see
//! [`dependency_inversion_candidates`]), and
//! [`Cohesion`](DesignPrinciple::Cohesion) (see [`cohesion_candidates`]). The
//! remaining `DesignPrinciple` variants are unused for now; they document the
//! target space rather than being implemented.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;
use syn::visit::Visit;

use crate::boundaries::{
    self, BoundaryConfig, BoundaryConfigError, MODULE_BOUNDARY_VIOLATION_RULE, ModuleBoundaryRule,
};
use crate::complexity::WorkspaceComplexity;
use crate::finding::{Finding, FindingId};
use crate::functions::walk_functions;
use crate::ingest::{CrateInfo, Workspace};
use crate::pattern::{CodeScope, Contraindication, Evidence, EvidenceLocation};

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

/// Collects every `pub fn`/`pub` impl-method signature in one parsed file
/// whose parameter or return type matches [`leaked_type_in`], tracking the
/// enclosing `mod`/`impl` path for a qualified item name (same path-tracking
/// shape as `crate::functions::walk_functions`' `Walker`, reimplemented here
/// because that helper doesn't expose parameter/return types).
struct SignatureCollector<'a> {
    path: Vec<String>,
    file: PathBuf,
    forbidden: &'a [String],
    hits: Vec<LeakedSignature>,
}

impl SignatureCollector<'_> {
    fn qualified(&self, name: &str) -> String {
        if self.path.is_empty() {
            name.to_string()
        } else {
            format!("{}::{name}", self.path.join("::"))
        }
    }

    fn check_signature(&mut self, item_path: &str, sig: &syn::Signature) {
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
            if let Some((leaked_type, forbidden)) = leaked_type_in(ty, self.forbidden) {
                self.hits.push(LeakedSignature {
                    item_path: item_path.to_string(),
                    leaked_type,
                    forbidden,
                    location: EvidenceLocation {
                        file: self.file.clone(),
                        item_path: Some(item_path.to_string()),
                    },
                });
            }
        }
    }
}

impl<'ast> Visit<'ast> for SignatureCollector<'_> {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if node.content.is_some() {
            self.path.push(node.ident.to_string());
            syn::visit::visit_item_mod(self, node);
            self.path.pop();
        } else {
            syn::visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        self.path.push(crate::functions::type_name(&node.self_ty));
        syn::visit::visit_item_impl(self, node);
        self.path.pop();
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if matches!(node.vis, syn::Visibility::Public(_)) {
            let item_path = self.qualified(&node.sig.ident.to_string());
            self.check_signature(&item_path, &node.sig);
        }
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if matches!(node.vis, syn::Visibility::Public(_)) {
            let item_path = self.qualified(&node.sig.ident.to_string());
            self.check_signature(&item_path, &node.sig);
        }
        syn::visit::visit_impl_item_fn(self, node);
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
        let mut collector = SignatureCollector {
            path: Vec::new(),
            file: source.path.clone(),
            forbidden,
            hits: Vec::new(),
        };
        collector.visit_file(&ast);
        leaks.extend(collector.hits);
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
}
