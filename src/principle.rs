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
//! sixteen table entries), plus two real detectors —
//! [`FunctionalCoreImperativeShell`](DesignPrinciple::FunctionalCoreImperativeShell)
//! (see [`functional_core_imperative_shell_candidates`]) and
//! [`InterfaceSegregation`](DesignPrinciple::InterfaceSegregation) (see
//! [`interface_segregation_candidates`]). The remaining `DesignPrinciple`
//! variants are unused for now; they document the target space rather than
//! being implemented.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;
use syn::visit::Visit;

use crate::complexity::WorkspaceComplexity;
use crate::finding::FindingId;
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
/// [`functional_core_imperative_shell_candidates`]. Merges its results with
/// [`interface_segregation_candidates`] — this is the dispatch point future
/// detectors from todo.md §16.7's table attach to.
pub fn analyze_workspace(
    workspace: &Workspace,
    complexity: &WorkspaceComplexity,
) -> Vec<PrincipleHeuristic> {
    let mut heuristics = functional_core_imperative_shell_candidates(workspace, complexity);
    heuristics.extend(interface_segregation_candidates(workspace));
    heuristics
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
    let mut cyclomatic_by_function: BTreeMap<(PathBuf, String), u32> = BTreeMap::new();
    for info in &complexity.functions {
        cyclomatic_by_function.insert(
            (info.file.clone(), info.qualified_name.clone()),
            info.cyclomatic,
        );
    }

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
        let source_files = workspace
            .crates
            .iter()
            .flat_map(|krate| krate.source_files.iter());
        let complexity = crate::complexity::analyze_workspace(source_files, false);
        analyze_workspace(workspace, &complexity)
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
        assert!(
            !heuristics.is_empty(),
            "fixture must produce a heuristic to check"
        );
        let principles: Vec<DesignPrinciple> = heuristics.iter().map(|h| h.principle).collect();
        assert!(
            principles.contains(&DesignPrinciple::FunctionalCoreImperativeShell)
                && principles.contains(&DesignPrinciple::InterfaceSegregation),
            "fixture must exercise both rules' wording: {principles:?}"
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
}
