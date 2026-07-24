//! Workspace-wide dead-code detection via the Deep Tier (see todo.md §3.A
//! "Reachability & Dead Code", §14.2 P1). Requires the `deep` feature —
//! semantic reachability isn't available at the Fast Tier.
//!
//! Scope: `unused-pub-workspace`/`unused-pub-api`, for free functions,
//! impl/trait methods ([`crate::functions::walk_functions`]'s items), and
//! top-level structs/enums/traits/consts/statics plus associated
//! consts/types inside impls ([`walk_type_items`], below); `dead-enum-variant`
//! for individual enum variants ([`walk_enum_variants`]); `test-only-pub` for
//! the same items `unused-pub-workspace`/`unused-pub-api` check.
//!
//! **Simplification, documented rather than hidden:** every workspace crate
//! is treated as workspace-internal for `dead-enum-variant` and
//! `test-only-pub` — todo.md §3.A's distinction between a real
//! `unused-pub-workspace` finding and an info-only `unused-pub-api` finding
//! on a *published* crate is only implemented for the top-level
//! function/type-item check below (see [`publishable_crates`]); the other
//! two rules don't yet narrow their scope by a crate's `publish` field
//! either.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use cargo_metadata::MetadataCommand;
use proc_macro2::Span;
use syn::visit::{self, Visit};

use crate::deep::{DeepContext, DeepError, FileId};
use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::functions::{type_name, walk_functions};
use crate::ingest::{SourceFile, Workspace};

pub const UNUSED_PUB_WORKSPACE_RULE: &str = "unused-pub-workspace";
/// Bump when the unused-pub-workspace rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const UNUSED_PUB_WORKSPACE_RULE_REVISION: u32 = 1;

/// The `unused-pub-workspace` sibling for a crate whose resolved `publish`
/// field allows publishing (see [`publishable_crates`]): the same
/// referencing_files + is_reachable_from_entry query, but `Info`/`Heuristic`
/// rather than `Warn`/`BoundedSemantic` — a published crate's whole purpose
/// is exposing API to consumers outside the loaded workspace, so "zero
/// internal reference" is the expected normal state for most of a healthy
/// library's public surface, not a defect signal (the same
/// `Severity::Info` + `EvidenceClass::Heuristic`, informational-only shape as
/// `heavy-dependency` in `crate::deps`). Classifying this `BoundedSemantic`
/// (gating) would fail CI for nearly every well-formed library crate.
pub const UNUSED_PUB_API_RULE: &str = "unused-pub-api";
/// Bump when the unused-pub-api rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const UNUSED_PUB_API_RULE_REVISION: u32 = 1;

/// An enum variant with no construction-position reference found anywhere in
/// the examined workspace view (see [`walk_enum_variants`],
/// [`check_enum_variant`]) — a variant only ever matched against, never
/// constructed, is a stronger and more specific signal than
/// `unused-pub-workspace` sees at the whole-item granularity `walk_type_items`
/// checks an enum at.
pub const DEAD_ENUM_VARIANT_RULE: &str = "dead-enum-variant";
/// Bump when the dead-enum-variant rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const DEAD_ENUM_VARIANT_RULE_REVISION: u32 = 1;

/// A `pub` item reachable only through `#[cfg(test)]`/test-target code —
/// unreachable in the "production" reachability mode but reachable in the
/// "all" mode, and with no cross-crate reference either (see
/// [`check_test_only_pub`]). Same v1 simplification as
/// `unused-pub-workspace`'s own module doc: every workspace crate is treated
/// as workspace-internal, so this doesn't yet narrow by a crate's `publish`
/// field the way `unused-pub-api` does for the top-level item check.
pub const TEST_ONLY_PUB_RULE: &str = "test-only-pub";
/// Bump when the test-only-pub rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const TEST_ONLY_PUB_RULE_REVISION: u32 = 1;

#[derive(Debug)]
pub enum DeadCodeError {
    Deep(DeepError),
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, syn::Error),
    Metadata(cargo_metadata::Error),
}

impl std::fmt::Display for DeadCodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deep(err) => write!(f, "{err}"),
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
            Self::Metadata(err) => write!(f, "failed to read cargo metadata: {err}"),
        }
    }
}

impl std::error::Error for DeadCodeError {}

#[derive(Debug, Default)]
pub struct WorkspaceDeadCode {
    pub findings: Vec<Finding>,
    pub errors: Vec<DeadCodeError>,
    /// Number of `pub` items/variants actually queried (functions, methods,
    /// structs, enums, traits, consts, enum variants — see todo.md §7,
    /// evidence for how thorough the run was, not just its findings). Each of
    /// `check_item`'s, `check_enum_variant`'s, and `check_test_only_pub`'s own
    /// query counts separately, so an item checked by more than one rule
    /// increments this more than once.
    pub checked: usize,
}

/// A `pub` struct/enum/trait/const/static declaration, or a `pub` associated
/// const/type inside an `impl` block, discovered while walking a file — the
/// type-level counterpart to [`crate::functions::walk_functions`]'s
/// function-like items. Anonymous consts (`const _: () = ...`) aren't
/// covered.
struct TypeItemSite<'ast> {
    qualified_name: String,
    ident_span: Span,
    vis: &'ast syn::Visibility,
}

/// Visits every top-level `struct`, `enum`, `trait`, `const`, and `static` in
/// `file`, plus every associated const/type inside an `impl` block, tracking
/// the enclosing `mod`/`impl`/`trait` path the same way
/// [`crate::functions::walk_functions`] does, so the two produce consistent
/// qualified names.
fn walk_type_items<'ast>(file: &'ast syn::File, on_item: impl FnMut(TypeItemSite<'ast>)) {
    struct Walker<F> {
        path: Vec<String>,
        on_item: F,
    }

    impl<F> Walker<F> {
        fn qualified_name(&self, name: &str) -> String {
            if self.path.is_empty() {
                name.to_string()
            } else {
                format!("{}::{name}", self.path.join("::"))
            }
        }
    }

    impl<'ast, F: FnMut(TypeItemSite<'ast>)> Walker<F> {
        fn emit(&mut self, name: &str, ident_span: Span, vis: &'ast syn::Visibility) {
            if name == "_" {
                return;
            }
            let qualified_name = self.qualified_name(name);
            (self.on_item)(TypeItemSite {
                qualified_name,
                ident_span,
                vis,
            });
        }
    }

    impl<'ast, F: FnMut(TypeItemSite<'ast>)> Visit<'ast> for Walker<F> {
        fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
            if node.content.is_some() {
                self.path.push(node.ident.to_string());
                visit::visit_item_mod(self, node);
                self.path.pop();
            } else {
                visit::visit_item_mod(self, node);
            }
        }

        fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
            self.emit(&node.ident.to_string(), node.ident.span(), &node.vis);
            visit::visit_item_struct(self, node);
        }

        fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
            self.emit(&node.ident.to_string(), node.ident.span(), &node.vis);
            visit::visit_item_enum(self, node);
        }

        fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
            self.emit(&node.ident.to_string(), node.ident.span(), &node.vis);
            self.path.push(node.ident.to_string());
            visit::visit_item_trait(self, node);
            self.path.pop();
        }

        fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
            self.path.push(type_name(&node.self_ty));
            visit::visit_item_impl(self, node);
            self.path.pop();
        }

        fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
            self.emit(&node.ident.to_string(), node.ident.span(), &node.vis);
            visit::visit_item_const(self, node);
        }

        fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
            self.emit(&node.ident.to_string(), node.ident.span(), &node.vis);
            visit::visit_item_static(self, node);
        }

        fn visit_impl_item_const(&mut self, node: &'ast syn::ImplItemConst) {
            self.emit(&node.ident.to_string(), node.ident.span(), &node.vis);
            visit::visit_impl_item_const(self, node);
        }

        fn visit_impl_item_type(&mut self, node: &'ast syn::ImplItemType) {
            self.emit(&node.ident.to_string(), node.ident.span(), &node.vis);
            visit::visit_impl_item_type(self, node);
        }
    }

    let mut walker = Walker {
        path: Vec::new(),
        on_item,
    };
    walker.visit_file(file);
}

/// A single `enum` variant discovered while walking a file — the
/// `dead-enum-variant` counterpart to [`TypeItemSite`], which only tracks the
/// enclosing `enum` as a whole. Deliberately a separate walker rather than a
/// change to [`walk_type_items`]: that function's per-enum (not per-variant)
/// shape is relied on by `unused-pub-workspace`'s existing item counting, and
/// changing it risks breaking that rule's behavior.
struct EnumVariantSite<'ast> {
    /// The enclosing enum's qualified name plus `::variant_name`, e.g.
    /// `outer::MyEnum::Variant` — matches `walk_type_items`'s naming scheme.
    qualified_name: String,
    /// The bare variant identifier (no enum/module prefix) — used to match
    /// construction-position occurrences in [`file_constructs_variant`],
    /// since a construction site only ever writes the variant's own trailing
    /// path segment (`MyEnum::Variant`, or bare `Variant` after `use
    /// MyEnum::Variant;`), never the qualified name this module computes.
    variant_name: String,
    ident_span: Span,
    /// `syn::Variant` has no `vis` field of its own — a variant's visibility
    /// is inherited from the enclosing `enum`.
    vis: &'ast syn::Visibility,
}

/// Visits every variant of every `enum` in `file`, tracking the enclosing
/// `mod` path the same way [`walk_type_items`] does.
fn walk_enum_variants<'ast>(file: &'ast syn::File, on_variant: impl FnMut(EnumVariantSite<'ast>)) {
    struct Walker<F> {
        path: Vec<String>,
        on_variant: F,
    }

    impl<F> Walker<F> {
        fn qualified_name(&self, name: &str) -> String {
            if self.path.is_empty() {
                name.to_string()
            } else {
                format!("{}::{name}", self.path.join("::"))
            }
        }
    }

    impl<'ast, F: FnMut(EnumVariantSite<'ast>)> Visit<'ast> for Walker<F> {
        fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
            if node.content.is_some() {
                self.path.push(node.ident.to_string());
                visit::visit_item_mod(self, node);
                self.path.pop();
            } else {
                visit::visit_item_mod(self, node);
            }
        }

        fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
            let enum_qualified_name = self.qualified_name(&node.ident.to_string());
            for variant in &node.variants {
                let variant_name = variant.ident.to_string();
                (self.on_variant)(EnumVariantSite {
                    qualified_name: format!("{enum_qualified_name}::{variant_name}"),
                    variant_name,
                    ident_span: variant.ident.span(),
                    vis: &node.vis,
                });
            }
            visit::visit_item_enum(self, node);
        }
    }

    let mut walker = Walker {
        path: Vec::new(),
        on_variant,
    };
    walker.visit_file(file);
}

/// Whether `ast` contains at least one construction-position occurrence of
/// `variant_name` as a path's trailing segment — `Expr::Path` (a unit
/// variant used as a bare value), `Expr::Call` (a tuple variant constructor;
/// its callee is itself an `Expr::Path`, so `visit_expr_path` already covers
/// it), or `Expr::Struct` (a struct variant literal). Deliberately does not
/// count a `Pat::TupleStruct`/`Pat::Struct` match/if-let occurrence (real,
/// distinct `syn` node kinds with their own `visit_pat_tuple_struct`/
/// `visit_pat_struct` callbacks, never dispatched through
/// `visit_expr_call`/`visit_expr_struct`) — [`crate::deep::referencing_files`]
/// only reports which files reference a position, not whether that reference
/// constructs or merely matches against it, so [`check_enum_variant`]
/// re-parses each referencing file with `syn` to tell the two apart.
///
/// **`Pat::Path` is a subtler case, handled explicitly rather than by node
/// kind alone:** `syn` defines `PatPath` as a type alias for `ExprPath` (see
/// `syn::pat`'s `pub use crate::expr::{.., ExprPath as PatPath, ..}), since a
/// bare `MyEnum::Variant` written in pattern position (`Status::Retired =>
/// ..`) and the identical text written in expression position
/// (`Status::Retired` as a value) parse to the exact same node — `syn`
/// itself doesn't distinguish the two by *kind*, only by *tree position*
/// (`Pat::Path` dispatches straight to `visit_expr_path`, bypassing
/// `visit_expr` entirely, so there is no separate `visit_pat_path` callback
/// to override). This visitor tracks that position explicitly via
/// `in_pattern`, toggled by `visit_pat`/`visit_expr` themselves, so a unit
/// variant used only as a match pattern is correctly not counted as a
/// construction even though it and a real construction share one node type.
///
/// **Known blind spot, documented rather than hidden:** `syn` parses a macro
/// invocation's input as an opaque token stream, not as `Expr`/`Pat` nodes —
/// a variant constructed only inside a macro call (e.g.
/// `some_macro!(MyEnum::Variant)`) is invisible to this scan even though
/// [`crate::deep::referencing_files`] (which resolves symbols through macro
/// expansion) correctly lists the containing file as a referencing file.
/// Matches the module's existing "im Zweifel nicht melden" stance
/// imperfectly: this is a genuine false-positive source, not yet closed.
fn file_constructs_variant(ast: &syn::File, variant_name: &str) -> bool {
    struct ConstructionVisitor<'a> {
        variant_name: &'a str,
        found: bool,
        /// Whether the node currently being visited is (transitively) part
        /// of a `Pat`, not an `Expr` — see this function's doc comment for
        /// why this can't be told apart by node kind alone for `Pat::Path`.
        in_pattern: bool,
    }

    fn path_ends_with(path: &syn::Path, name: &str) -> bool {
        path.segments.last().is_some_and(|segment| segment.ident == name)
    }

    impl<'a, 'ast> Visit<'ast> for ConstructionVisitor<'a> {
        fn visit_pat(&mut self, node: &'ast syn::Pat) {
            let previously_in_pattern = self.in_pattern;
            self.in_pattern = true;
            visit::visit_pat(self, node);
            self.in_pattern = previously_in_pattern;
        }

        fn visit_expr(&mut self, node: &'ast syn::Expr) {
            let previously_in_pattern = self.in_pattern;
            self.in_pattern = false;
            visit::visit_expr(self, node);
            self.in_pattern = previously_in_pattern;
        }

        fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
            if !self.in_pattern && path_ends_with(&node.path, self.variant_name) {
                self.found = true;
            }
            visit::visit_expr_path(self, node);
        }

        fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
            if !self.in_pattern && path_ends_with(&node.path, self.variant_name) {
                self.found = true;
            }
            visit::visit_expr_struct(self, node);
        }
    }

    let mut visitor = ConstructionVisitor {
        variant_name,
        found: false,
        in_pattern: false,
    };
    visitor.visit_file(ast);
    visitor.found
}

/// Workspace member crate names with at least one direct (`normal` or
/// `build`, not `dev`) dependency whose own compiled target is a proc-macro
/// (`cargo_metadata::Target::is_proc_macro`). Attached to
/// `unused-pub-workspace` findings (see `check_item`) as a
/// `proc_macro_expansion_disabled` limitation: [`crate::deep::DeepContext::load`]
/// loads with `ProcMacroServerChoice::None`, so `find_all_refs` can never see
/// a caller that only exists in a proc-macro's expanded output (see the
/// `a_pub_fn_reachable_only_through_an_unexpanded_proc_macro_derive_is_falsely_flagged_dead`
/// test below), and a crate that pulls in a proc-macro dependency is exactly
/// where that blind spot can bite.
///
/// **Crate-wide, over-approximate signal — not item-level.** This answers
/// "does this crate have a proc-macro dependency", not "is this specific
/// item proc-macro-reachable" — the analysis has no way to narrow the signal
/// down that far without actually expanding the macro (out of scope; see
/// todo.md §2.1). Attaching the limitation to every `unused-pub-workspace`
/// finding in an exposed crate, rather than trying to guess which findings
/// are actually affected, is the same "im Zweifel nicht [fälschlich sicher]
/// melden" stance the rest of this module takes: more disclosure than
/// strictly necessary is safer than missing a real blind spot.
///
/// Needs a full (non-`--no-deps`) `cargo metadata` resolve: [`crate::ingest::load`]
/// runs `cargo metadata --no-deps` (see its module doc), which never fetches
/// a dependency's own package/target metadata — only the workspace members'
/// declared dependencies are visible that way. [`crate::dep_graph`] needs the
/// same full resolve for its own rules and documents why in its module doc;
/// this runs its own `cargo_metadata::MetadataCommand`, once per
/// [`analyze_workspace`] call, following that module's pattern rather than
/// sharing its `Metadata` value — neither `dead_code` nor `ingest` currently
/// holds one already loaded, and threading dep_graph's through would widen
/// that module's API for a dependency this module doesn't otherwise need.
fn proc_macro_exposed_crates(
    workspace_root: &Path,
) -> Result<HashSet<String>, cargo_metadata::Error> {
    let manifest_path = workspace_root.join("Cargo.toml");
    let metadata = MetadataCommand::new()
        .manifest_path(&manifest_path)
        .exec()?;

    let proc_macro_packages: HashSet<&cargo_metadata::PackageId> = metadata
        .packages
        .iter()
        .filter(|package| {
            package
                .targets
                .iter()
                .any(cargo_metadata::Target::is_proc_macro)
        })
        .map(|package| &package.id)
        .collect();

    let Some(resolve) = &metadata.resolve else {
        return Ok(HashSet::new());
    };

    let mut exposed = HashSet::new();
    for member_id in &metadata.workspace_members {
        let Some(node) = resolve.nodes.iter().find(|node| &node.id == member_id) else {
            continue;
        };
        let has_direct_proc_macro_dep = node.deps.iter().any(|dep| {
            proc_macro_packages.contains(&dep.pkg)
                && dep.dep_kinds.iter().any(|dep_kind| {
                    matches!(
                        dep_kind.kind,
                        cargo_metadata::DependencyKind::Normal
                            | cargo_metadata::DependencyKind::Build
                    )
                })
        });
        if has_direct_proc_macro_dep
            && let Some(package) = metadata.packages.iter().find(|pkg| &pkg.id == member_id)
        {
            exposed.insert(package.name.clone());
        }
    }
    Ok(exposed)
}

/// Workspace member crate names whose resolved `publish` field allows
/// publishing — `cargo_metadata::Package::publish` is `None` (no `publish`
/// key at all, or a bare `publish = true`) or `Some(non_empty_list)` (a
/// restricted registry list); only `Some(empty_list)` means `publish =
/// false`. Drives `unused-pub-api` vs. `unused-pub-workspace`: an item in a
/// publishable crate's whole purpose is exposing API to consumers outside
/// the loaded workspace, so a zero-reference finding there is informational
/// (`unused-pub-api`), not the same signal as in a crate that will never
/// leave this workspace (`unused-pub-workspace`).
///
/// Runs its own `cargo_metadata::MetadataCommand` call, same pattern and same
/// rationale as [`proc_macro_exposed_crates`] (see that function's doc
/// comment) — a full, non-`--no-deps` resolve is needed to see `publish` at
/// all, since [`crate::ingest::load`]'s own `--no-deps` resolve only reads
/// the workspace member manifests' dependency declarations.
fn publishable_crates(workspace_root: &Path) -> Result<HashSet<String>, cargo_metadata::Error> {
    let manifest_path = workspace_root.join("Cargo.toml");
    let metadata = MetadataCommand::new()
        .manifest_path(&manifest_path)
        .exec()?;

    Ok(metadata
        .packages
        .iter()
        .filter(|package| metadata.workspace_members.contains(&package.id))
        .filter(|package| {
            package
                .publish
                .as_ref()
                .is_none_or(|registries| !registries.is_empty())
        })
        .map(|package| package.name.clone())
        .collect())
}

/// Checks one `pub` item for cross-crate usage and records a finding if
/// neither that nor entry-point reachability found it live — the shared
/// logic both [`walk_functions`]'s and [`walk_type_items`]'s callbacks
/// funnel into.
///
/// The entry-point check matters most for single-crate workspaces — the
/// common case — where cross-crate usage is vacuously impossible (there is
/// no other crate), which would otherwise make every `pub` item look
/// unused. An item reachable from its own crate's `fn main` is genuinely
/// live even with zero cross-crate references (see
/// [`crate::reachability::is_reachable_from_entry`]'s own entry-point scope
/// caveats — this inherits them).
///
/// `rule_id`/`severity`/`evidence_class`/`reason` are parameterized rather
/// than hardcoded so this one query can back both `unused-pub-workspace` and
/// `unused-pub-api` (see [`publishable_crates`]) — the two rules share
/// exactly the same reachability mechanism and differ only in how a
/// publishable crate's "nothing referenced it in this workspace" result
/// should be read.
#[allow(clippy::too_many_arguments)]
fn check_item(
    analysis: &ra_ap_ide::Analysis,
    crate_of_file: &HashMap<FileId, &str>,
    entry_keys: &std::collections::HashSet<(FileId, u32)>,
    proc_macro_exposed: &HashSet<String>,
    file: &SourceFile,
    file_id: FileId,
    krate_name: &str,
    qualified_name: &str,
    offset: u32,
    line: usize,
    include_tests: bool,
    rule_id: &str,
    severity: Severity,
    evidence_class: EvidenceClass,
    reason: &str,
    report: &mut WorkspaceDeadCode,
) {
    report.checked += 1;
    let position = ra_ap_ide::FilePosition {
        file_id,
        offset: offset.into(),
    };

    let referencing = match crate::deep::referencing_files(analysis, position, include_tests) {
        Ok(referencing) => referencing,
        Err(err) => {
            report.errors.push(DeadCodeError::Deep(err));
            return;
        }
    };
    let used_externally = referencing.iter().any(|referencing_file| {
        crate_of_file
            .get(referencing_file)
            .is_some_and(|owner| *owner != krate_name)
    });
    if used_externally {
        return;
    }

    match crate::reachability::is_reachable_from_entry(
        analysis,
        entry_keys,
        position,
        include_tests,
    ) {
        Ok(true) => {}
        Ok(false) => {
            let searched_crates: std::collections::HashSet<&str> =
                crate_of_file.values().copied().collect();
            let mut evidence = serde_json::json!({
                "tier": "deep",
                "searched_crates": searched_crates.len(),
                "references_found": referencing.len(),
                "root_set_size": entry_keys.len(),
                "reason": reason,
            });
            if proc_macro_exposed.contains(krate_name) {
                evidence["limitations"] = serde_json::json!(["proc_macro_expansion_disabled"]);
            }
            report.findings.push(Finding {
                id: format!("{rule_id}:{}:{qualified_name}", file.path.display()).into(),
                rule: rule_id.into(),
                severity,
                location: Location {
                    file: file.path.clone(),
                    line: OneBasedLine::new(line).expect("source line numbers are 1-based"),
                    item_path: qualified_name.to_string(),
                },
                evidence_class,
                origin: Origin::Code,
                evidence: Some(evidence),
                caused_by: Vec::new(),
                causes: Vec::new(),
            });
        }
        Err(err) => report.errors.push(reachability_error(err)),
    }
}

/// `check_item`'s `reason` text for `unused-pub-workspace` (see
/// [`UNUSED_PUB_WORKSPACE_RULE`]) — a factored-out constant so both the real
/// call site in [`analyze_workspace`] and its tests can refer to the exact
/// wording.
const UNUSED_PUB_WORKSPACE_REASON: &str = "no reference from another workspace crate and \
    unreachable from any recognized entry point (fn main in a [[bin]] or [[example]] target)";

/// `check_item`'s `reason` text for `unused-pub-api` (see
/// [`UNUSED_PUB_API_RULE`]) — matches `unused-pub-workspace`'s "no reference
/// found" wording pattern, extended with the "this crate is published, so
/// external ecosystem usage is not inferable and expected" clause its
/// `RULE_REGISTRY` entry requires (todo.md §17.3, §17.4).
const UNUSED_PUB_API_REASON: &str = "no reference found within the examined workspace; this \
    crate is published, so external ecosystem usage is not inferable and expected";

/// Converts a [`crate::reachability::ReachabilityError`] into the closest
/// matching [`DeadCodeError`] variant, so the two modules' errors can share
/// one `errors` list.
fn reachability_error(err: crate::reachability::ReachabilityError) -> DeadCodeError {
    use crate::reachability::ReachabilityError;
    match err {
        ReachabilityError::Deep(deep_err) => DeadCodeError::Deep(deep_err),
        ReachabilityError::Io(path, io_err) => DeadCodeError::Io(path, io_err),
        ReachabilityError::Parse(path, parse_err) => DeadCodeError::Parse(path, parse_err),
        ReachabilityError::UnknownItem(item) => {
            DeadCodeError::Deep(DeepError::Cancelled(format!("unknown item: {item}")))
        }
        // `find_item_position`'s ambiguity is only reachable via `--why-live`'s
        // CLI item-path lookup — `analyze_workspace` never calls it.
        ReachabilityError::AmbiguousItem(item, _) => {
            DeadCodeError::Deep(DeepError::Cancelled(format!("ambiguous item: {item}")))
        }
    }
}

/// Checks one enum variant for a construction-position reference anywhere in
/// the examined workspace view — `dead-enum-variant`. Unlike [`check_item`],
/// this does not consult reachability from an entry point at all: a variant
/// that is genuinely constructed somewhere is live regardless of whether the
/// surrounding code happens to be reachable from `fn main`, so the only
/// question is whether a construction site exists anywhere.
///
/// `file_path_by_id` narrows the candidate set before re-parsing: only files
/// [`crate::deep::referencing_files`] already reports as referencing the
/// variant's position are re-parsed with `syn` to classify the reference
/// (see [`file_constructs_variant`]) — the same crate-wide simplification
/// `unused-pub-workspace`'s own module doc documents (every workspace crate
/// counts as workspace-internal) applies here too, unmodified.
#[allow(clippy::too_many_arguments)]
fn check_enum_variant(
    analysis: &ra_ap_ide::Analysis,
    file_path_by_id: &HashMap<FileId, PathBuf>,
    file: &SourceFile,
    file_id: FileId,
    qualified_name: &str,
    variant_name: &str,
    offset: u32,
    line: usize,
    include_tests: bool,
    report: &mut WorkspaceDeadCode,
) {
    report.checked += 1;
    let position = ra_ap_ide::FilePosition {
        file_id,
        offset: offset.into(),
    };

    let referencing = match crate::deep::referencing_files(analysis, position, include_tests) {
        Ok(referencing) => referencing,
        Err(err) => {
            report.errors.push(DeadCodeError::Deep(err));
            return;
        }
    };

    let mut construction_found = false;
    for referencing_file_id in &referencing {
        let Some(path) = file_path_by_id.get(referencing_file_id) else {
            continue;
        };
        let source = match std::fs::read_to_string(path) {
            Ok(source) => source,
            Err(err) => {
                report.errors.push(DeadCodeError::Io(path.clone(), err));
                continue;
            }
        };
        let ast = match syn::parse_file(&source) {
            Ok(ast) => ast,
            Err(err) => {
                report.errors.push(DeadCodeError::Parse(path.clone(), err));
                continue;
            }
        };
        if file_constructs_variant(&ast, variant_name) {
            construction_found = true;
            break;
        }
    }

    if construction_found {
        return;
    }

    let evidence = serde_json::json!({
        "tier": "deep",
        "referencing_files": referencing.len(),
        "reason": "no construction site found in the examined workspace view",
    });
    report.findings.push(Finding {
        id: format!(
            "{DEAD_ENUM_VARIANT_RULE}:{}:{qualified_name}",
            file.path.display()
        )
        .into(),
        rule: DEAD_ENUM_VARIANT_RULE.into(),
        severity: Severity::Warn,
        location: Location {
            file: file.path.clone(),
            line: OneBasedLine::new(line).expect("source line numbers are 1-based"),
            item_path: qualified_name.to_string(),
        },
        evidence_class: EvidenceClass::BoundedSemantic,
        origin: Origin::Code,
        evidence: Some(evidence),
        caused_by: Vec::new(),
        causes: Vec::new(),
    });
}

/// Checks one `pub` item for `test-only-pub`: reachable only through
/// `#[cfg(test)]`/test-target code, not in production, and not referenced
/// from another workspace crate either. Calls
/// [`crate::reachability::is_reachable_from_entry`] twice — once against the
/// "production" root set (`include_tests: false`), once against the "all"
/// root set (`include_tests: true`) — since todo.md §3.A's two reachability
/// modes are exactly what distinguishes "genuinely dead" from "alive only
/// because tests exercise it". Real, accepted extra query volume per item
/// (see this module's `TEST_ONLY_PUB_RULE` doc comment); restructuring
/// [`analyze_workspace`] to compute both modes in one pass is out of scope
/// here.
///
/// Same v1 simplification as `unused-pub-workspace`: every workspace crate is
/// treated as workspace-internal, so this doesn't attempt `unused-pub-api`'s
/// `publish`-field-aware narrowing either.
#[allow(clippy::too_many_arguments)]
fn check_test_only_pub(
    analysis: &ra_ap_ide::Analysis,
    crate_of_file: &HashMap<FileId, &str>,
    entry_keys_production: &std::collections::HashSet<(FileId, u32)>,
    entry_keys_all: &std::collections::HashSet<(FileId, u32)>,
    file: &SourceFile,
    file_id: FileId,
    krate_name: &str,
    qualified_name: &str,
    offset: u32,
    line: usize,
    report: &mut WorkspaceDeadCode,
) {
    report.checked += 1;
    let position = ra_ap_ide::FilePosition {
        file_id,
        offset: offset.into(),
    };

    // The cross-crate check uses the "all" search — a reference from another
    // workspace crate's test code is still evidence this item has a life
    // outside its own crate, the same disqualifying condition `check_item`
    // applies.
    let referencing = match crate::deep::referencing_files(analysis, position, true) {
        Ok(referencing) => referencing,
        Err(err) => {
            report.errors.push(DeadCodeError::Deep(err));
            return;
        }
    };
    let used_externally = referencing.iter().any(|referencing_file| {
        crate_of_file
            .get(referencing_file)
            .is_some_and(|owner| *owner != krate_name)
    });
    if used_externally {
        return;
    }

    let production_reachable = match crate::reachability::is_reachable_from_entry(
        analysis,
        entry_keys_production,
        position,
        false,
    ) {
        Ok(reachable) => reachable,
        Err(err) => {
            report.errors.push(reachability_error(err));
            return;
        }
    };
    if production_reachable {
        // Reachable in production already — not test-only.
        return;
    }

    let all_reachable = match crate::reachability::is_reachable_from_entry(
        analysis,
        entry_keys_all,
        position,
        true,
    ) {
        Ok(reachable) => reachable,
        Err(err) => {
            report.errors.push(reachability_error(err));
            return;
        }
    };
    if !all_reachable {
        // Unreachable even with tests counted — `unused-pub-workspace`'s/
        // `unused-pub-api`'s territory, not this rule's.
        return;
    }

    let searched_crates: std::collections::HashSet<&str> =
        crate_of_file.values().copied().collect();
    let evidence = serde_json::json!({
        "tier": "deep",
        "searched_crates": searched_crates.len(),
        "references_found": referencing.len(),
        "root_set_size_production": entry_keys_production.len(),
        "root_set_size_all": entry_keys_all.len(),
        "reason": "reachable only through #[cfg(test)]/test-target code in the examined \
            workspace view",
    });
    report.findings.push(Finding {
        id: format!(
            "{TEST_ONLY_PUB_RULE}:{}:{qualified_name}",
            file.path.display()
        )
        .into(),
        rule: TEST_ONLY_PUB_RULE.into(),
        severity: Severity::Warn,
        location: Location {
            file: file.path.clone(),
            line: OneBasedLine::new(line).expect("source line numbers are 1-based"),
            item_path: qualified_name.to_string(),
        },
        evidence_class: EvidenceClass::BoundedSemantic,
        origin: Origin::Code,
        evidence: Some(evidence),
        caused_by: Vec::new(),
        causes: Vec::new(),
    });
}

/// Finds `pub` functions/methods referenced only from their own defining
/// crate — or not at all — never from another workspace crate. This is
/// `unused-pub-workspace`, todo.md §3.A's "Kernregel": exposing something as
/// `pub` that nothing outside the crate uses only widens the API surface;
/// `pub(crate)` would do the same job with a smaller footprint.
///
/// `include_tests` selects between the "production" and "all" reachability
/// modes from todo.md §3.A — a reference only from a `#[test]` doesn't count
/// as external use when `include_tests` is `false`. `test-only-pub` (see
/// [`check_test_only_pub`]) needs both modes regardless of this parameter, so
/// both are computed unconditionally below.
pub fn analyze_workspace(
    workspace: &Workspace,
    include_tests: bool,
) -> Result<WorkspaceDeadCode, DeadCodeError> {
    let ctx = DeepContext::load(&workspace.root).map_err(DeadCodeError::Deep)?;
    let analysis = ctx.analysis();

    let mut crate_of_file: HashMap<FileId, &str> = HashMap::new();
    let mut file_path_by_id: HashMap<FileId, PathBuf> = HashMap::new();
    for krate in &workspace.crates {
        for file in &krate.source_files {
            if let Some(file_id) = ctx.file_id(&file.path) {
                crate_of_file.insert(file_id, krate.name.as_str());
                file_path_by_id.insert(file_id, file.path.clone());
            }
        }
    }

    let entries_production = crate::reachability::entry_point_positions(workspace, &ctx, false)
        .map_err(reachability_error)?;
    let entry_keys_production: std::collections::HashSet<(FileId, u32)> = entries_production
        .iter()
        .map(|(_, position)| crate::reachability::position_key(*position))
        .collect();
    let entries_all = crate::reachability::entry_point_positions(workspace, &ctx, true)
        .map_err(reachability_error)?;
    let entry_keys_all: std::collections::HashSet<(FileId, u32)> = entries_all
        .iter()
        .map(|(_, position)| crate::reachability::position_key(*position))
        .collect();
    let entry_keys = if include_tests {
        &entry_keys_all
    } else {
        &entry_keys_production
    };

    let mut report = WorkspaceDeadCode::default();

    let proc_macro_exposed = match proc_macro_exposed_crates(&workspace.root) {
        Ok(exposed) => exposed,
        Err(err) => {
            report.errors.push(DeadCodeError::Metadata(err));
            HashSet::new()
        }
    };
    // On a metadata failure, an empty set conservatively treats every crate
    // as non-publishable — falling back to the stricter, gating
    // `unused-pub-workspace` rather than silently downgrading a real finding
    // to `unused-pub-api`'s `Info`/advisory-only shape.
    let publishable = match publishable_crates(&workspace.root) {
        Ok(publishable) => publishable,
        Err(err) => {
            report.errors.push(DeadCodeError::Metadata(err));
            HashSet::new()
        }
    };

    for krate in &workspace.crates {
        let (rule_id, severity, evidence_class, reason) = if publishable.contains(&krate.name) {
            (
                UNUSED_PUB_API_RULE,
                Severity::Info,
                EvidenceClass::Heuristic,
                UNUSED_PUB_API_REASON,
            )
        } else {
            (
                UNUSED_PUB_WORKSPACE_RULE,
                Severity::Warn,
                EvidenceClass::BoundedSemantic,
                UNUSED_PUB_WORKSPACE_REASON,
            )
        };

        for file in &krate.source_files {
            if !file.kind.is_locally_reportable() {
                continue;
            }
            let Some(file_id) = ctx.file_id(&file.path) else {
                // Not indexed by the loader (e.g. excluded, or the loader
                // failed to discover this target) — nothing to query.
                continue;
            };

            let source = match std::fs::read_to_string(&file.path) {
                Ok(source) => source,
                Err(err) => {
                    report
                        .errors
                        .push(DeadCodeError::Io(file.path.clone(), err));
                    continue;
                }
            };
            let ast = match syn::parse_file(&source) {
                Ok(ast) => ast,
                Err(err) => {
                    report
                        .errors
                        .push(DeadCodeError::Parse(file.path.clone(), err));
                    continue;
                }
            };

            walk_functions(&ast, |site| {
                let Some(syn::Visibility::Public(_)) = site.vis else {
                    return;
                };
                let offset = site.ident_span.byte_range().start as u32;
                let line = site.ident_span.start().line;
                check_item(
                    &analysis,
                    &crate_of_file,
                    entry_keys,
                    &proc_macro_exposed,
                    file,
                    file_id,
                    &krate.name,
                    &site.qualified_name,
                    offset,
                    line,
                    include_tests,
                    rule_id,
                    severity,
                    evidence_class,
                    reason,
                    &mut report,
                );
                check_test_only_pub(
                    &analysis,
                    &crate_of_file,
                    &entry_keys_production,
                    &entry_keys_all,
                    file,
                    file_id,
                    &krate.name,
                    &site.qualified_name,
                    offset,
                    line,
                    &mut report,
                );
            });

            walk_type_items(&ast, |site| {
                if !matches!(site.vis, syn::Visibility::Public(_)) {
                    return;
                }
                let offset = site.ident_span.byte_range().start as u32;
                let line = site.ident_span.start().line;
                check_item(
                    &analysis,
                    &crate_of_file,
                    entry_keys,
                    &proc_macro_exposed,
                    file,
                    file_id,
                    &krate.name,
                    &site.qualified_name,
                    offset,
                    line,
                    include_tests,
                    rule_id,
                    severity,
                    evidence_class,
                    reason,
                    &mut report,
                );
                check_test_only_pub(
                    &analysis,
                    &crate_of_file,
                    &entry_keys_production,
                    &entry_keys_all,
                    file,
                    file_id,
                    &krate.name,
                    &site.qualified_name,
                    offset,
                    line,
                    &mut report,
                );
            });

            walk_enum_variants(&ast, |site| {
                if !matches!(site.vis, syn::Visibility::Public(_)) {
                    return;
                }
                check_enum_variant(
                    &analysis,
                    &file_path_by_id,
                    file,
                    file_id,
                    &site.qualified_name,
                    &site.variant_name,
                    site.ident_span.byte_range().start as u32,
                    site.ident_span.start().line,
                    include_tests,
                    &mut report,
                );
            });
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::test_util::TempDir;

    fn load_single_crate_workspace(dir: &TempDir, lib_source: &str) -> Workspace {
        load_single_crate_workspace_with_edition(dir, "2021", lib_source)
    }

    fn load_single_crate_workspace_with_edition(
        dir: &TempDir,
        edition: &str,
        lib_source: &str,
    ) -> Workspace {
        std::fs::write(
            dir.join("Cargo.toml"),
            format!(
                r#"
[package]
name = "dead-code-fixture"
version = "0.1.0"
edition = "{edition}"
"#
            ),
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), lib_source).unwrap();

        crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap()
    }

    fn write_crate(dir: &TempDir, name: &str, deps: &[(&str, &str)], lib_source: &str) {
        std::fs::create_dir_all(dir.join(name).join("src")).unwrap();
        let mut manifest =
            format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n");
        if !deps.is_empty() {
            manifest.push_str("\n[dependencies]\n");
            for (dep_name, rel_path) in deps {
                manifest.push_str(&format!("{dep_name} = {{ path = \"{rel_path}\" }}\n"));
            }
        }
        std::fs::write(dir.join(name).join("Cargo.toml"), manifest).unwrap();
        std::fs::write(dir.join(name).join("src/lib.rs"), lib_source).unwrap();
    }

    fn write_workspace_manifest(dir: &TempDir, members: &[&str]) {
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

    #[test]
    fn a_pub_fn_called_from_another_workspace_crate_is_not_flagged() {
        let dir = TempDir::new("dead-code-cross-crate");
        write_crate(
            &dir,
            "core",
            &[],
            r#"pub fn used_by_consumer() -> i32 {
    1
}

pub fn never_called() -> i32 {
    2
}
"#,
        );
        write_crate(
            &dir,
            "consumer",
            &[("core", "../core")],
            r#"pub fn run() -> i32 {
    core::used_by_consumer()
}
"#,
        );
        write_workspace_manifest(&dir, &["core", "consumer"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();
        let names: Vec<_> = report
            .findings
            .iter()
            .map(|f| f.location.item_path.as_str())
            .collect();

        assert!(
            !names.contains(&"used_by_consumer"),
            "called from `consumer`, a different workspace crate — must not be flagged"
        );
        assert!(
            names.contains(&"never_called"),
            "never referenced anywhere — must be flagged"
        );
    }

    #[test]
    fn does_not_flag_a_completely_unused_private_fn() {
        let dir = TempDir::new("dead-code-private-fn");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"fn private_and_unused() -> i32 {
    1
}
"#,
        );

        let report = analyze_workspace(&workspace, true).unwrap();

        assert!(report.findings.is_empty());
        assert_eq!(report.checked, 0);
    }

    #[test]
    fn finding_shape_matches_the_documented_contract() {
        // `publish = false` keeps this crate out of `unused-pub-api`'s scope
        // (see `publishable_crates`) — this test documents
        // `unused-pub-workspace`'s own finding shape specifically.
        let dir = TempDir::new("dead-code-finding-shape");
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "dead-code-fixture"
version = "0.1.0"
edition = "2021"
publish = false
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            r#"pub fn never_called() -> i32 {
    1
}
"#,
        )
        .unwrap();
        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let report = analyze_workspace(&workspace, true).unwrap();

        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.rule, UNUSED_PUB_WORKSPACE_RULE);
        assert_eq!(finding.severity, Severity::Warn);
        assert_eq!(finding.origin, Origin::Code);
        assert_eq!(finding.evidence_class, EvidenceClass::BoundedSemantic);
        assert_eq!(finding.location.item_path, "never_called");

        let evidence = finding.evidence.as_ref().expect("evidence must be present");
        assert_eq!(evidence["tier"], "deep");
        assert_eq!(evidence["searched_crates"], 1);
        assert_eq!(evidence["references_found"], 0);
        assert_eq!(evidence["root_set_size"], 0);
        assert!(evidence["reason"].is_string());
    }

    #[test]
    fn structs_enums_traits_and_consts_are_checked_the_same_way_as_functions() {
        let dir = TempDir::new("dead-code-type-items");
        write_crate(
            &dir,
            "core",
            &[],
            r#"pub struct UsedStruct;
pub struct DeadStruct;

pub enum UsedEnum {
    A,
}
pub enum DeadEnum {
    A,
}

pub trait UsedTrait {}
pub trait DeadTrait {}

pub const USED_CONST: i32 = 1;
pub const DEAD_CONST: i32 = 2;
"#,
        );
        write_crate(
            &dir,
            "consumer",
            &[("core", "../core")],
            r#"struct Local;
impl core::UsedTrait for Local {}

pub fn run() -> i32 {
    let _ = core::UsedStruct;
    let _ = core::UsedEnum::A;
    core::USED_CONST
}
"#,
        );
        write_workspace_manifest(&dir, &["core", "consumer"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();
        let names: HashSet<&str> = report
            .findings
            .iter()
            .map(|f| f.location.item_path.as_str())
            .collect();

        for used in ["UsedStruct", "UsedEnum", "UsedTrait", "USED_CONST"] {
            assert!(
                !names.contains(used),
                "{used} is referenced from `consumer` and must not be flagged"
            );
        }
        for dead in ["DeadStruct", "DeadEnum", "DeadTrait", "DEAD_CONST"] {
            assert!(
                names.contains(dead),
                "{dead} is never referenced and must be flagged"
            );
        }
    }

    #[test]
    fn associated_consts_types_and_statics_are_checked_the_same_way_as_functions() {
        let dir = TempDir::new("dead-code-assoc-items-and-statics");
        write_crate(
            &dir,
            "core",
            &[],
            r#"pub struct Widget;

impl Widget {
    pub const USED_ASSOC_CONST: i32 = 1;
    pub const DEAD_ASSOC_CONST: i32 = 2;
}

pub trait Converter {
    type Output;
}

impl Converter for Widget {
    type Output = i32;
}

pub static USED_STATIC: i32 = 1;
pub static DEAD_STATIC: i32 = 2;
"#,
        );
        write_crate(
            &dir,
            "consumer",
            &[("core", "../core")],
            r#"pub fn run() -> i32 {
    core::USED_STATIC + core::Widget::USED_ASSOC_CONST
}
"#,
        );
        write_workspace_manifest(&dir, &["core", "consumer"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();
        let names: HashSet<&str> = report
            .findings
            .iter()
            .map(|f| f.location.item_path.as_str())
            .collect();

        for used in ["Widget::USED_ASSOC_CONST", "USED_STATIC"] {
            assert!(
                !names.contains(used),
                "{used} is referenced from `consumer` and must not be flagged"
            );
        }
        for dead in ["Widget::DEAD_ASSOC_CONST", "DEAD_STATIC"] {
            assert!(
                names.contains(dead),
                "{dead} is never referenced and must be flagged"
            );
        }
    }

    #[test]
    fn a_private_struct_is_not_checked() {
        let dir = TempDir::new("dead-code-private-struct");
        let workspace = load_single_crate_workspace(&dir, "struct PrivateStruct;\n");

        let report = analyze_workspace(&workspace, true).unwrap();

        assert!(report.findings.is_empty());
        assert_eq!(report.checked, 0);
    }

    #[test]
    fn a_single_crate_workspace_does_not_flag_items_reachable_from_its_own_main() {
        // The common case this closes a real gap for: a single-crate
        // workspace has no "other crate" to ever reference anything, so the
        // cross-crate check alone would flag the entire public API. An item
        // reachable from this crate's own `fn main` is genuinely live.
        let dir = TempDir::new("dead-code-single-crate-entry");
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "dead-code-fixture"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src/bin")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            r#"pub fn used_by_main() -> i32 {
    1
}

pub fn truly_dead() -> i32 {
    2
}
"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("src/bin/tool.rs"),
            r#"fn main() {
    dead_code_fixture::used_by_main();
}
"#,
        )
        .unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();
        let names: HashSet<&str> = report
            .findings
            .iter()
            .map(|f| f.location.item_path.as_str())
            .collect();

        assert!(
            !names.contains("used_by_main"),
            "reachable from this crate's own `fn main` — must not be flagged even with no cross-crate reference"
        );
        assert!(
            names.contains("truly_dead"),
            "never referenced anywhere — must be flagged"
        );
    }

    #[test]
    fn an_item_only_used_by_a_no_mangle_export_is_not_flagged() {
        let dir = TempDir::new("dead-code-no-mangle-entry");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"pub fn used_by_export() -> i32 {
    1
}

pub fn truly_dead() -> i32 {
    2
}

#[no_mangle]
pub extern "C" fn exported() -> i32 {
    used_by_export()
}
"#,
        );

        let report = analyze_workspace(&workspace, false).unwrap();
        let names: HashSet<&str> = report
            .findings
            .iter()
            .map(|f| f.location.item_path.as_str())
            .collect();

        assert!(
            !names.contains("used_by_export"),
            "reachable from a #[no_mangle] export — must not be flagged even in production-only mode"
        );
        assert!(
            names.contains("truly_dead"),
            "never referenced anywhere — must be flagged"
        );
    }

    /// The Rust-2024 unsafe-attribute spellings — `#[unsafe(no_mangle)]` and
    /// `#[unsafe(export_name = "...")]` — mark external roots exactly like
    /// their bare pre-2024 forms (see
    /// [`an_item_only_used_by_a_no_mangle_export_is_not_flagged`]). The
    /// fixture is `edition = "2024"` because `unsafe(...)` in attributes is
    /// only valid syntax from that edition on.
    #[test]
    fn an_item_only_used_by_an_unsafe_wrapped_export_is_not_flagged() {
        let dir = TempDir::new("dead-code-unsafe-attr-entry");
        let workspace = load_single_crate_workspace_with_edition(
            &dir,
            "2024",
            r#"pub fn used_by_no_mangle_export() -> i32 {
    1
}

pub fn used_by_export_name_export() -> i32 {
    2
}

pub fn truly_dead() -> i32 {
    3
}

#[unsafe(no_mangle)]
pub extern "C" fn exported_a() -> i32 {
    used_by_no_mangle_export()
}

#[unsafe(export_name = "exported_b_symbol")]
pub extern "C" fn exported_b() -> i32 {
    used_by_export_name_export()
}
"#,
        );

        let report = analyze_workspace(&workspace, false).unwrap();
        let names: HashSet<&str> = report
            .findings
            .iter()
            .map(|f| f.location.item_path.as_str())
            .collect();

        assert!(
            !names.contains("used_by_no_mangle_export"),
            "reachable from a #[unsafe(no_mangle)] export — must not be flagged"
        );
        assert!(
            !names.contains("used_by_export_name_export"),
            "reachable from a #[unsafe(export_name = ...)] export — must not be flagged"
        );
        assert!(
            names.contains("truly_dead"),
            "never referenced anywhere — must be flagged"
        );
    }

    /// A position the Deep Tier cannot semantically resolve — here literally
    /// on whitespace instead of on an identifier, the same probe
    /// `crate::deep`'s own three-state test uses — must be collected as an
    /// analyzer error and must never become a dead-code finding. Before the
    /// three-state query modeling (todo.md §15.1), `find_all_refs`'s `None`
    /// was collapsed into "zero references" and turned into exactly the
    /// finding this test forbids. Exercised through [`check_item`] directly
    /// because `analyze_workspace`'s positions always come from syn ident
    /// spans, which by construction sit on identifiers.
    #[test]
    fn an_unresolvable_position_is_a_collected_error_not_a_finding() {
        let dir = TempDir::new("dead-code-unresolvable-position");
        let lib_source = "pub fn item() -> i32 {\n    1\n}\n";
        let workspace = load_single_crate_workspace(&dir, lib_source);

        let ctx = DeepContext::load(&workspace.root).unwrap();
        let analysis = ctx.analysis();
        let krate = &workspace.crates[0];
        let file = krate
            .source_files
            .iter()
            .find(|file| file.path.ends_with("src/lib.rs"))
            .unwrap();
        let file_id = ctx.file_id(&file.path).unwrap();
        let crate_of_file = HashMap::from([(file_id, krate.name.as_str())]);
        let entry_keys = std::collections::HashSet::new();

        // Strictly inside the body's indentation whitespace — no symbol.
        let offset = lib_source.find("    1").unwrap() as u32 + 1;

        let mut report = WorkspaceDeadCode::default();
        let proc_macro_exposed = HashSet::new();
        check_item(
            &analysis,
            &crate_of_file,
            &entry_keys,
            &proc_macro_exposed,
            file,
            file_id,
            &krate.name,
            "not_a_symbol",
            offset,
            2,
            true,
            UNUSED_PUB_WORKSPACE_RULE,
            Severity::Warn,
            EvidenceClass::BoundedSemantic,
            UNUSED_PUB_WORKSPACE_REASON,
            &mut report,
        );

        assert!(
            report.findings.is_empty(),
            "an unresolvable position must never become a dead-code finding: {:?}",
            report.findings
        );
        assert!(
            report
                .errors
                .iter()
                .any(|err| matches!(err, DeadCodeError::Deep(DeepError::UnresolvedSymbol(_)))),
            "the failed resolution must be collected as an analyzer error: {:?}",
            report.errors
        );
    }

    /// **Known gap, documented rather than hidden — not a regression to fix
    /// here.** todo.md §3.A/§7 requires that proc-macro blind spots produce
    /// `analysis_incomplete` rather than a finding ("im Zweifel nicht
    /// melden" — a false positive costs more trust than ten false negatives
    /// are worth; todo.md line 1696 lists "Proc-Macros und unbekannte
    /// Consumer" explicitly among the cases that must come back
    /// `analysis_incomplete`). [`crate::deep::DeepContext::load`] already
    /// documents *why* this can't hold today: the Deep Tier loads with
    /// `ProcMacroServerChoice::None`, so a proc-macro-derive's generated
    /// code is never expanded and never enters rust-analyzer's semantic
    /// model at all.
    ///
    /// This matters for `unused-pub-workspace` specifically: unlike the
    /// unresolvable-position case above (an item whose *own* position fails
    /// to resolve, caught by [`DeepError::UnresolvedSymbol`]), here `helper`
    /// itself resolves perfectly fine — it's the *caller*, hidden inside
    /// unexpanded macro output, that's invisible. `find_all_refs` therefore
    /// legitimately answers "zero references" (`Some(empty)`, not `None`),
    /// so the three-state error handling that protects the
    /// unresolvable-position case doesn't fire here — there's no error to
    /// collect. `helper` is only reachable via the derive's expansion (never
    /// called from anywhere the analysis can see), so it is genuinely
    /// flagged dead, contradicting the documented policy. Fixing this needs
    /// proc-macro-usage detection across the workspace, a real feature, not
    /// a small fix — pinning down today's actual behavior here so the gap
    /// is tracked rather than silently assumed away.
    ///
    /// **Partial mitigation:** [`proc_macro_exposed_crates`] can't eliminate
    /// this false positive (that needs real proc-macro expansion), but since
    /// `core` here has a direct proc-macro dependency, the finding for
    /// `helper` now carries `"limitations": ["proc_macro_expansion_disabled"]`
    /// in its evidence — the uncertainty is surfaced instead of hidden behind
    /// an unqualified `unused-pub-workspace` warning.
    #[test]
    fn a_pub_fn_reachable_only_through_an_unexpanded_proc_macro_derive_is_falsely_flagged_dead() {
        let dir = TempDir::new("dead-code-proc-macro-blind-spot");
        std::fs::create_dir_all(dir.join("macros/src")).unwrap();
        std::fs::write(
            dir.join("macros/Cargo.toml"),
            r#"[package]
name = "macros"
version = "0.1.0"
edition = "2021"

[lib]
proc-macro = true
"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("macros/src/lib.rs"),
            r#"use proc_macro::TokenStream;

/// Would-be expansion (never actually run — the Deep Tier loads with no
/// proc-macro server): a call to `helper()` the analysis never sees.
#[proc_macro_derive(CallsHelper)]
pub fn calls_helper(_input: TokenStream) -> TokenStream {
    "fn __generated_caller() { crate::helper(); }".parse().unwrap()
}
"#,
        )
        .unwrap();
        write_crate(
            &dir,
            "core",
            &[("macros", "../macros")],
            r#"#[derive(macros::CallsHelper)]
pub struct Widget;

pub fn helper() -> i32 {
    1
}

pub fn truly_dead() -> i32 {
    2
}
"#,
        );
        write_workspace_manifest(&dir, &["macros", "core"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();
        let names: HashSet<&str> = report
            .findings
            .iter()
            .map(|f| f.location.item_path.as_str())
            .collect();

        assert!(
            report.errors.is_empty(),
            "no analyzer error is raised for this case today — `helper` resolves fine, only its \
             caller is invisible: {:?}",
            report.errors
        );
        assert!(
            names.contains("helper"),
            "documents today's actual (policy-violating) behavior: `helper` is only reachable \
             through the derive's unexpanded generated code, so it is flagged dead instead of \
             producing analysis_incomplete — see this test's doc comment"
        );
        assert!(
            names.contains("truly_dead"),
            "genuinely dead regardless — control for the fixture"
        );

        let helper_finding = report
            .findings
            .iter()
            .find(|f| f.location.item_path == "helper")
            .expect("helper must be flagged, per the assertion above");
        let evidence = helper_finding
            .evidence
            .as_ref()
            .expect("evidence must be present");
        assert_eq!(
            evidence["limitations"],
            serde_json::json!(["proc_macro_expansion_disabled"]),
            "`core` has a direct proc-macro dependency (`macros`), so the finding must disclose \
             that proc-macro expansion was disabled instead of presenting `helper` as an \
             unqualified dead-code finding: {evidence:?}"
        );
    }

    /// A crate whose `unused-pub-workspace` finding has nothing to do with a
    /// proc-macro derive at all — the dead item and the proc-macro
    /// dependency are unrelated — still gets the disclosure, because
    /// [`proc_macro_exposed_crates`] is deliberately crate-wide, not
    /// item-level (see that function's doc comment): the analysis can't tell
    /// whether *this specific* finding is affected, only that the crate has
    /// a proc-macro dependency somewhere, so it discloses on every finding in
    /// that crate.
    #[test]
    fn a_pub_item_in_a_proc_macro_exposed_crate_discloses_the_limitation() {
        let dir = TempDir::new("dead-code-proc-macro-exposed-limitation");
        std::fs::create_dir_all(dir.join("macros/src")).unwrap();
        std::fs::write(
            dir.join("macros/Cargo.toml"),
            r#"[package]
name = "macros"
version = "0.1.0"
edition = "2021"

[lib]
proc-macro = true
"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("macros/src/lib.rs"),
            r#"use proc_macro::TokenStream;

#[proc_macro]
pub fn noop(_input: TokenStream) -> TokenStream {
    TokenStream::new()
}
"#,
        )
        .unwrap();
        write_crate(
            &dir,
            "core",
            &[("macros", "../macros")],
            r#"pub fn never_called() -> i32 {
    1
}
"#,
        );
        write_workspace_manifest(&dir, &["macros", "core"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();

        let finding = report
            .findings
            .iter()
            .find(|f| f.location.item_path == "never_called")
            .expect("never_called must be flagged dead");
        let evidence = finding.evidence.as_ref().expect("evidence must be present");
        assert_eq!(
            evidence["limitations"],
            serde_json::json!(["proc_macro_expansion_disabled"]),
            "`core` directly depends on the proc-macro crate `macros`, so the finding must \
             disclose that proc-macro expansion was disabled, even though this particular dead \
             item is unrelated to the derive: {evidence:?}"
        );
    }

    /// The negative control for the disclosure above: a workspace with no
    /// proc-macro dependency anywhere must not carry the `limitations` field
    /// at all — an always-present empty array would blur the signal between
    /// "checked, no proc-macro exposure" and "checked, exposure found".
    #[test]
    fn a_pub_item_in_a_crate_without_any_proc_macro_dependency_has_no_limitations() {
        let dir = TempDir::new("dead-code-no-proc-macro-dependency");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"pub fn never_called() -> i32 {
    1
}
"#,
        );

        let report = analyze_workspace(&workspace, true).unwrap();

        let finding = report
            .findings
            .iter()
            .find(|f| f.location.item_path == "never_called")
            .expect("never_called must be flagged dead");
        let evidence = finding.evidence.as_ref().expect("evidence must be present");
        assert!(
            evidence.get("limitations").is_none(),
            "no proc-macro dependency anywhere in this workspace — the finding must not carry a \
             `limitations` field: {evidence:?}"
        );
    }

    /// Regression test for a fixed false positive: [`crate::deep`]'s
    /// `CargoConfig` used to never activate any non-default Cargo feature
    /// (it only overrode `sysroot`/`set_test`, leaving `features` at
    /// `ra_ap_project_model::CargoConfig::default()`'s `Selected { features:
    /// vec![], no_default_features: false }` — default features only). A
    /// caller reachable only through a non-default, non-enabled feature was
    /// invisible the same way a proc-macro-only caller is: the position
    /// resolves fine (`Some`, not `None`), so no [`DeepError::UnresolvedSymbol`]
    /// fired — it just never showed up in `helper`'s incoming calls, and
    /// `check_item`'s [`crate::reachability::is_reachable_from_entry`] BFS
    /// (this rule's actual same-crate liveness test, not raw reference
    /// counting — see `check_item`'s doc comment) never found a path to it,
    /// even though a real `cargo build --features extra` (or
    /// `--all-features`, as CI commonly runs) would show it reachable. That
    /// violated todo.md §3.A/§7's "im Zweifel nicht melden" stance.
    ///
    /// The caller here has to itself be a recognized entry point (a
    /// `#[test]`, gated the same way `#[cfg(test)]` test modules normally
    /// are) rather than just any `pub fn` — [`walk_functions`] discovers
    /// `#[test]`-attributed functions syntactically regardless of `cfg`, but
    /// [`crate::reachability::is_reachable_from_entry`]'s BFS still needs the
    /// feature-gated function to *semantically resolve* to reach `helper`
    /// through it. A caller that is itself just an ordinary, uncalled `pub
    /// fn` wouldn't do: it would stay unreachable-from-any-entry-point
    /// regardless of the feature fix, which would make this test pass for
    /// the wrong reason.
    ///
    /// [`crate::deep::DeepContext::load`] now loads the workspace with
    /// `CargoFeatures::All` (`--all-features`-equivalent), so the `extra`
    /// feature is active, the test function resolves as a live entry point,
    /// and `helper` is reachable through it — no finding for `helper`
    /// anymore.
    #[test]
    fn a_pub_fn_reachable_only_through_a_non_default_cargo_feature_is_not_flagged_dead() {
        let dir = TempDir::new("dead-code-feature-gate-blind-spot");
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "dead-code-fixture"
version = "0.1.0"
edition = "2021"

[features]
extra = []
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            r#"pub fn helper() -> i32 {
    1
}

#[cfg(feature = "extra")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calls_helper() {
        assert_eq!(helper(), 1);
    }
}
"#,
        )
        .unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();
        // Scoped to the `unused-pub-workspace`/`unused-pub-api` rule family
        // this test is actually about — `helper` is also reachable only
        // through `calls_helper`'s test in "production" mode (the feature
        // gate makes no difference there), so `test-only-pub` correctly
        // fires for it separately; that is not what this regression test
        // guards against.
        let names: HashSet<&str> = report
            .findings
            .iter()
            .filter(|f| f.rule == UNUSED_PUB_WORKSPACE_RULE || f.rule == UNUSED_PUB_API_RULE)
            .map(|f| f.location.item_path.as_str())
            .collect();

        assert!(
            report.errors.is_empty(),
            "no analyzer error is raised for this case today: {:?}",
            report.errors
        );
        assert!(
            !names.contains("helper"),
            "`helper` is called from `calls_helper`, a #[test] fn only active with the \
             non-default `extra` feature — now that the Deep Tier loads with all features, the \
             test is a live entry point and `helper` must not be flagged dead"
        );
    }

    // -- unused-pub-api ---------------------------------------------------

    #[test]
    fn a_dead_pub_item_in_a_publishable_crate_is_flagged_unused_pub_api() {
        // No `publish` field set at all — publishable by default (see
        // `publishable_crates`), so the top-level dead-item check routes
        // through `unused-pub-api`, not `unused-pub-workspace`.
        let dir = TempDir::new("dead-code-unused-pub-api");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"pub fn never_called() -> i32 {
    1
}
"#,
        );

        let report = analyze_workspace(&workspace, true).unwrap();

        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.rule, UNUSED_PUB_API_RULE);
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.evidence_class, EvidenceClass::Heuristic);
        assert_eq!(finding.location.item_path, "never_called");

        let evidence = finding.evidence.as_ref().expect("evidence must be present");
        assert_eq!(evidence["reason"], serde_json::json!(UNUSED_PUB_API_REASON));
    }

    #[test]
    fn a_dead_pub_item_in_a_publish_false_crate_stays_unused_pub_workspace() {
        let dir = TempDir::new("dead-code-publish-false");
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "dead-code-fixture"
version = "0.1.0"
edition = "2021"
publish = false
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            r#"pub fn never_called() -> i32 {
    1
}
"#,
        )
        .unwrap();
        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let report = analyze_workspace(&workspace, true).unwrap();

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule, UNUSED_PUB_WORKSPACE_RULE);
        assert_eq!(report.findings[0].severity, Severity::Warn);
        assert_eq!(
            report.findings[0].evidence_class,
            EvidenceClass::BoundedSemantic
        );
    }

    #[test]
    fn a_dead_pub_item_in_a_crate_restricted_to_a_registry_is_still_flagged_unused_pub_api() {
        // `publish = ["some-internal-registry"]` is `Some(non_empty_list)` —
        // still publishable per `cargo_metadata::Package::publish`'s
        // documented semantics, only `Some(vec![])` means `publish = false`.
        let dir = TempDir::new("dead-code-restricted-registry");
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "dead-code-fixture"
version = "0.1.0"
edition = "2021"
publish = ["some-internal-registry"]
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            r#"pub fn never_called() -> i32 {
    1
}
"#,
        )
        .unwrap();
        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let report = analyze_workspace(&workspace, true).unwrap();

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule, UNUSED_PUB_API_RULE);
    }

    // -- dead-enum-variant ------------------------------------------------

    #[test]
    fn an_enum_variant_never_constructed_is_flagged_dead_enum_variant() {
        let dir = TempDir::new("dead-code-enum-variant-dead");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"pub enum Status {
    Active,
    Retired,
}

pub fn describe(status: Status) -> &'static str {
    match status {
        Status::Active => "active",
        Status::Retired => "retired",
    }
}

pub fn make() -> Status {
    Status::Active
}
"#,
        );

        let report = analyze_workspace(&workspace, true).unwrap();
        let dead_variants: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.rule == DEAD_ENUM_VARIANT_RULE)
            .collect();

        assert_eq!(dead_variants.len(), 1, "{dead_variants:?}");
        let finding = dead_variants[0];
        assert_eq!(finding.location.item_path, "Status::Retired");
        assert_eq!(finding.severity, Severity::Warn);
        assert_eq!(finding.evidence_class, EvidenceClass::BoundedSemantic);
        assert_eq!(
            finding.evidence.as_ref().unwrap()["reason"],
            serde_json::json!("no construction site found in the examined workspace view")
        );
    }

    #[test]
    fn an_enum_variant_constructed_only_in_another_workspace_crate_is_not_flagged() {
        let dir = TempDir::new("dead-code-enum-variant-cross-crate");
        write_crate(
            &dir,
            "core",
            &[],
            r#"pub enum Status {
    Active,
}
"#,
        );
        write_crate(
            &dir,
            "consumer",
            &[("core", "../core")],
            r#"pub fn make() -> core::Status {
    core::Status::Active
}
"#,
        );
        write_workspace_manifest(&dir, &["core", "consumer"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();

        let dead_variants: Vec<&str> = report
            .findings
            .iter()
            .filter(|f| f.rule == DEAD_ENUM_VARIANT_RULE)
            .map(|f| f.location.item_path.as_str())
            .collect();

        assert!(
            dead_variants.is_empty(),
            "Status::Active is constructed from `consumer`, a different workspace crate: \
             {dead_variants:?}"
        );
    }

    #[test]
    fn a_variant_of_a_private_enum_is_not_checked() {
        let dir = TempDir::new("dead-code-enum-variant-private");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"enum Status {
    Active,
    Retired,
}
"#,
        );

        let report = analyze_workspace(&workspace, true).unwrap();

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == DEAD_ENUM_VARIANT_RULE),
            "a private enum's variants are rustc's own dead_code lint's job, not this rule's"
        );
    }

    // -- test-only-pub -----------------------------------------------------

    #[test]
    fn a_pub_fn_reachable_only_from_a_test_is_flagged_test_only_pub() {
        let dir = TempDir::new("dead-code-test-only-pub");
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "dead-code-fixture"
version = "0.1.0"
edition = "2021"
publish = false
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src/bin")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            r#"pub fn test_only_helper() -> i32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test() {
        assert_eq!(test_only_helper(), 1);
    }
}
"#,
        )
        .unwrap();
        std::fs::write(dir.join("src/bin/tool.rs"), "fn main() {}\n").unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        // `include_tests: true` so the top-level `unused-pub-workspace` check
        // sees the same "all" reachability `test-only-pub` does, and does
        // not also fire for the same item — isolating this test to the
        // signal it is actually about.
        let report = analyze_workspace(&workspace, true).unwrap();

        let test_only_pub_findings: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.rule == TEST_ONLY_PUB_RULE)
            .collect();
        assert_eq!(test_only_pub_findings.len(), 1, "{:?}", report.findings);
        let finding = test_only_pub_findings[0];
        assert_eq!(finding.location.item_path, "test_only_helper");
        assert_eq!(finding.severity, Severity::Warn);
        assert_eq!(finding.evidence_class, EvidenceClass::BoundedSemantic);

        assert!(
            !report.findings.iter().any(|f| f.location.item_path
                == "test_only_helper"
                && f.rule != TEST_ONLY_PUB_RULE),
            "test_only_helper is reachable via the test entry point in \"all\" mode, so \
             unused-pub-workspace/unused-pub-api must not also fire for it: {:?}",
            report.findings
        );
    }

    #[test]
    fn a_pub_fn_reachable_from_main_is_not_flagged_test_only_pub() {
        let dir = TempDir::new("dead-code-test-only-pub-negative-main");
        std::fs::create_dir_all(dir.join("src/bin")).unwrap();
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "dead-code-fixture"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            r#"pub fn used_by_main() -> i32 {
    1
}
"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("src/bin/tool.rs"),
            r#"fn main() {
    dead_code_fixture::used_by_main();
}
"#,
        )
        .unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();

        assert!(
            !report.findings.iter().any(|f| f.rule == TEST_ONLY_PUB_RULE),
            "used_by_main is reachable from main in production too — must not be flagged \
             test-only-pub: {:?}",
            report.findings
        );
    }

    #[test]
    fn a_pub_fn_used_by_another_workspace_crate_is_not_flagged_test_only_pub_even_if_also_tested()
     {
        let dir = TempDir::new("dead-code-test-only-pub-cross-crate");
        write_crate(
            &dir,
            "core",
            &[],
            r#"pub fn shared() -> i32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test() {
        assert_eq!(shared(), 1);
    }
}
"#,
        );
        write_crate(
            &dir,
            "consumer",
            &[("core", "../core")],
            r#"pub fn run() -> i32 {
    core::shared()
}
"#,
        );
        write_workspace_manifest(&dir, &["core", "consumer"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == TEST_ONLY_PUB_RULE && f.location.item_path == "shared"),
            "`shared` is referenced from `consumer`, a different workspace crate — must not be \
             flagged test-only-pub even though it also has a #[cfg(test)] caller: {:?}",
            report.findings
        );
    }

    /// Directly exercises the `syn`-level construction/pattern
    /// classification (no Deep Tier needed) — the specific regression this
    /// guards against: `syn`'s `PatPath` is a type alias for `ExprPath` (see
    /// `file_constructs_variant`'s doc comment), so a naive
    /// `visit_expr_path`-only classifier would wrongly count a unit variant
    /// used only in a match arm's pattern as "constructed".
    #[test]
    fn file_constructs_variant_does_not_count_a_bare_pattern_match_as_construction() {
        let ast: syn::File = syn::parse_str(
            r#"
pub enum Status {
    Active,
    Retired,
}

pub fn describe(status: Status) -> &'static str {
    match status {
        Status::Active => "active",
        Status::Retired => "retired",
    }
}

pub fn make() -> Status {
    Status::Active
}
"#,
        )
        .unwrap();

        assert!(
            file_constructs_variant(&ast, "Active"),
            "Active is constructed in `make`"
        );
        assert!(
            !file_constructs_variant(&ast, "Retired"),
            "Retired only ever appears as a match-arm pattern, never constructed"
        );
    }

    /// The registry's curated `example.before` for this rule (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// this is what keeps a landing-page-facing example from silently
    /// drifting away from what judge actually flags.
    #[cfg(feature = "deep")]
    #[test]
    fn unused_pub_workspace_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(UNUSED_PUB_WORKSPACE_RULE)
            .expect("unused-pub-workspace has a registry entry")
            .example
            .expect("unused-pub-workspace has a curated example")
            .before;

        let dir = TempDir::new("dead-code-unused-pub-workspace-registry-example");
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "dead-code-fixture"
version = "0.1.0"
edition = "2021"
publish = false
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), example).unwrap();
        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let report = analyze_workspace(&workspace, true).unwrap();

        assert_eq!(
            report
                .findings
                .iter()
                .filter(|f| f.rule == UNUSED_PUB_WORKSPACE_RULE)
                .count(),
            1,
            "{:?}",
            report.findings
        );
    }

    /// See `unused_pub_workspace_registry_example_still_triggers_the_rule`'s
    /// doc comment.
    #[cfg(feature = "deep")]
    #[test]
    fn unused_pub_api_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(UNUSED_PUB_API_RULE)
            .expect("unused-pub-api has a registry entry")
            .example
            .expect("unused-pub-api has a curated example")
            .before;

        let dir = TempDir::new("dead-code-unused-pub-api-registry-example");
        let workspace = load_single_crate_workspace(&dir, example);

        let report = analyze_workspace(&workspace, true).unwrap();

        assert_eq!(
            report
                .findings
                .iter()
                .filter(|f| f.rule == UNUSED_PUB_API_RULE)
                .count(),
            1,
            "{:?}",
            report.findings
        );
    }

    /// See `unused_pub_workspace_registry_example_still_triggers_the_rule`'s
    /// doc comment.
    #[cfg(feature = "deep")]
    #[test]
    fn dead_enum_variant_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(DEAD_ENUM_VARIANT_RULE)
            .expect("dead-enum-variant has a registry entry")
            .example
            .expect("dead-enum-variant has a curated example")
            .before;

        let dir = TempDir::new("dead-code-dead-enum-variant-registry-example");
        let workspace = load_single_crate_workspace(&dir, example);

        let report = analyze_workspace(&workspace, true).unwrap();

        assert_eq!(
            report
                .findings
                .iter()
                .filter(|f| f.rule == DEAD_ENUM_VARIANT_RULE)
                .count(),
            1,
            "{:?}",
            report.findings
        );
    }

    /// See `unused_pub_workspace_registry_example_still_triggers_the_rule`'s
    /// doc comment.
    #[cfg(feature = "deep")]
    #[test]
    fn test_only_pub_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(TEST_ONLY_PUB_RULE)
            .expect("test-only-pub has a registry entry")
            .example
            .expect("test-only-pub has a curated example")
            .before;

        let dir = TempDir::new("dead-code-test-only-pub-registry-example");
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "dead-code-fixture"
version = "0.1.0"
edition = "2021"
publish = false
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src/bin")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), example).unwrap();
        std::fs::write(dir.join("src/bin/tool.rs"), "fn main() {}\n").unwrap();
        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let report = analyze_workspace(&workspace, true).unwrap();

        assert_eq!(
            report
                .findings
                .iter()
                .filter(|f| f.rule == TEST_ONLY_PUB_RULE)
                .count(),
            1,
            "{:?}",
            report.findings
        );
    }
}
