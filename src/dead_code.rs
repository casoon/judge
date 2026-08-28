//! Workspace-wide dead-code detection via the Deep Tier (see todo.md §3.A
//! "Reachability & Dead Code", §14.2 P1). Requires the `deep` feature —
//! semantic reachability isn't available at the Fast Tier.
//!
//! Scope: `unused-pub-workspace`/`unused-pub-api`, for free functions,
//! impl/trait methods ([`crate::functions::walk_functions`]'s items), and
//! top-level structs/enums/traits/consts/statics plus associated
//! consts/types inside impls ([`walk_type_items`], below); `dead-enum-variant`
//! for individual enum variants ([`walk_enum_variants`]); `test-only-pub` for
//! the same items `unused-pub-workspace`/`unused-pub-api` check;
//! `unreachable-from-entry` for the same [`walk_functions`]/[`walk_type_items`]
//! items but scoped to non-`pub` visibility instead — `pub` items stay
//! `unused-pub-workspace`/`unused-pub-api`/`test-only-pub`'s territory (see
//! [`UNREACHABLE_FROM_ENTRY_RULE`]).
//!
//! **Simplification, documented rather than hidden:** every workspace crate
//! is treated as workspace-internal for `dead-enum-variant` and
//! `test-only-pub` — todo.md §3.A's distinction between a real
//! `unused-pub-workspace` finding and an info-only `unused-pub-api` finding
//! on a *published* crate is only implemented for the top-level
//! function/type-item check below (see [`publishable_crates`]); the other
//! two rules don't yet narrow their scope by a crate's `publish` field
//! either.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use cargo_metadata::MetadataCommand;
use proc_macro2::Span;
use syn::visit::{self, Visit};

use crate::boundaries::module_path_for_file;
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

/// A non-`pub` item (private, `pub(crate)`, `pub(super)`, `pub(in path)`)
/// with no path from any recognized entry point in the examined
/// reachability view (see [`check_unreachable_from_entry`]) — todo.md §3.A's
/// standalone rule, closing the gap where
/// [`crate::reachability::is_reachable_from_entry`]'s reverse-BFS previously
/// only backed `--why-live`'s path search, with no Finding-producing rule of
/// its own.
///
/// Deliberately scoped to non-`pub` items only: a `pub` item's
/// unreachability is already fully owned by `unused-pub-workspace`/
/// `unused-pub-api`/`test-only-pub` above — this rule does not duplicate
/// their cross-crate reference check ([`check_item`]'s `used_externally`) at
/// all, since a non-`pub` item cannot be referenced from another crate by
/// Rust's own visibility rules; that check would be vacuously false here.
/// Unlike [`crate::slop_structural_deep`]'s fan-in check, this does *not*
/// exclude trait-impl methods (`FunctionSite::in_trait_impl`): that
/// exclusion exists there because its literal-reference search
/// ([`crate::deep::referencing_files`]) can't see calls through
/// operator/macro sugar, but [`crate::reachability::is_reachable_from_entry`]
/// walks `incoming_calls`, rust-analyzer's semantic call hierarchy, which
/// does resolve calls through trait dispatch (see
/// `crate::reachability::classify_call_kind`'s `Dynamic`/`Static`
/// distinction) — the same blind spot doesn't apply here.
pub const UNREACHABLE_FROM_ENTRY_RULE: &str = "unreachable-from-entry";
/// Bump when the unreachable-from-entry rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const UNREACHABLE_FROM_ENTRY_RULE_REVISION: u32 = 1;

/// A workspace crate's cross-crate coupling, expressed as Robert C. Martin's
/// Instability metric `I = Ce / (Ca + Ce)` from *Agile Software Development:
/// Principles, Patterns, and Practices* — the same named-formula posture
/// `crate::git`'s Gini-based `size-distribution`/`complexity-concentration`
/// already take. `Ce` (efferent coupling) is the number of distinct other
/// workspace crates this crate references code from; `Ca` (afferent
/// coupling) is the number of distinct other workspace crates that reference
/// code from this crate. Both counts fall directly out of [`check_item`]'s
/// existing [`crate::deep::referencing_files`] call — this rule adds no new
/// Deep-Tier query of its own, only a side-aggregation over the full
/// `referencing` set that call already computes for every `pub` item in the
/// workspace (see `edge_counts` in [`analyze_workspace`]). A crate with
/// `Ca + Ce == 0` (no cross-crate coupling observed at all) is skipped, not
/// flagged — there is nothing to report. `I` itself is never interpreted as
/// good or bad: a shared core crate is *expected* to have high afferent
/// coupling, so this is a purely descriptive, distributional signal (see
/// `crate::rule_registry`'s entry for this rule).
pub const CRATE_COUPLING_RULE: &str = "crate-coupling";
/// Bump when the crate-coupling rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const CRATE_COUPLING_RULE_REVISION: u32 = 1;

/// [`CRATE_COUPLING_RULE`], generalized down from crate granularity to
/// *top-level module* granularity — the other half of todo.md §C's "Fan-in/
/// Fan-out auf Modul-/Crate-Ebene" item (the crate-level half is
/// `crate-coupling`, above). Same Martin's Instability `I = Ce / (Ca + Ce)`
/// computation, same `edge_counts`-style side-aggregation over
/// [`check_item`]'s existing per-`pub`-item [`crate::deep::referencing_files`]
/// call (no second Deep-Tier pass), same "skip if `Ca + Ce == 0`" gate, and
/// the same never-good-or-bad, purely descriptive posture as
/// `crate-coupling` (see that rule's doc comment).
///
/// **Grouping: top-level module within each crate, not the full nested
/// module path.** A module here means `krate_name::first_module_segment`
/// (e.g. `mycrate::parser`, `mycrate::codegen`) — an item several levels
/// deep (`mycrate::parser::ast::visitor`) is folded into its crate's
/// `parser` bucket, not kept as its own bucket. A full arbitrarily-deep
/// grouping would fragment into too many tiny, low-signal buckets on a
/// large codebase, the same "keep it bounded" concern this module's other
/// coupling rule already addresses via its skip-if-zero gate. An item
/// declared directly at a crate's root (`src/lib.rs`, `src/main.rs`, or a
/// `src/bin/*.rs` target — not inside any named module at all) gets its own
/// `krate_name::<root>` bucket rather than being silently dropped or merged
/// into an arbitrary sibling.
///
/// **Module identity comes from [`crate::boundaries::module_path_for_file`],
/// not a fresh per-item AST walk.** An item's own module is resolved from
/// the *file* it's declared in — the same directory/`mod.rs` convention
/// resolver `module-boundary-violation`/`module-boundary-violation-deep`
/// already rely on for exactly this "which module is this file in"
/// question — rather than tracking `mod { .. }` nesting from scratch:
/// [`crate::functions::walk_functions`]'s/[`walk_type_items`]'s own
/// `path`-tracking only records *inline* `mod` blocks written within the
/// same file being walked (each walk starts a fresh, empty path per file);
/// it has no notion of the file-to-file `mod foo;` linkage that gives most
/// real-world crates their `mycrate::parser`/`mycrate::codegen`-shaped
/// module tree in the first place. Reusing that per-file tracking alone
/// would misclassify nearly every item in a typical multi-file crate
/// (including this workspace's own) as crate-root, which would defeat the
/// rule's purpose entirely — `module_path_for_file`'s existing, precedented
/// file-based resolution is the correct fit.
///
/// **Broader scope than `crate-coupling`: same-crate cross-module coupling
/// counts too, not just cross-crate.** Unlike `crate-coupling` (which only
/// has cross-crate references to look at — [`crate::deep::referencing_files`]
/// resolving to a *different* workspace crate is the only kind of edge that
/// rule's `edge_counts` accumulates), a reference from a file in module A to
/// an item defined in module B counts here whether A and B live in the same
/// crate or in two different workspace crates — module coupling is a
/// meaningful signal within a single large crate, not only across a crate
/// boundary.
pub const MODULE_COUPLING_RULE: &str = "module-coupling";
/// Bump when the module-coupling rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const MODULE_COUPLING_RULE_REVISION: u32 = 1;

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
            Self::Io(path, err) => fmt_io_error(f, path, err),
            Self::Parse(path, err) => fmt_parse_error(f, path, err),
            Self::Metadata(err) => write!(f, "failed to read cargo metadata: {err}"),
        }
    }
}

impl std::error::Error for DeadCodeError {}

/// Renders a failed-file-read error the same way every Deep-Tier error enum
/// in this crate does — [`DeadCodeError::Io`],
/// [`crate::reachability::ReachabilityError::Io`], and
/// [`crate::boundaries_deep::BoundaryDeepError::Io`] all wrap the same
/// `(path, std::io::Error)` pair and render it identically; only their other,
/// rule-specific variants differ.
pub(crate) fn fmt_io_error(
    f: &mut std::fmt::Formatter<'_>,
    path: &Path,
    err: &std::io::Error,
) -> std::fmt::Result {
    write!(f, "{}: failed to read file: {err}", path.display())
}

/// Renders a failed-parse error — see [`fmt_io_error`]'s doc comment; the
/// same sharing rationale applies to [`DeadCodeError::Parse`],
/// [`crate::reachability::ReachabilityError::Parse`], and
/// [`crate::boundaries_deep::BoundaryDeepError::Parse`].
pub(crate) fn fmt_parse_error(
    f: &mut std::fmt::Formatter<'_>,
    path: &Path,
    err: &syn::Error,
) -> std::fmt::Result {
    write!(f, "{}: failed to parse: {err}", path.display())
}

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
pub(crate) struct TypeItemSite<'ast> {
    pub(crate) qualified_name: String,
    pub(crate) ident_span: Span,
    pub(crate) vis: &'ast syn::Visibility,
}

/// Generates the standard visitor callback for declaration kinds that only
/// need to be emitted and then traversed. Module, trait, and impl callbacks
/// intentionally remain explicit because they additionally manage `path`.
macro_rules! visit_emitted_type_item {
    ($method:ident, $node:ty, $traverse:ident) => {
        fn $method(&mut self, node: &'ast $node) {
            self.emit(&node.ident.to_string(), node.ident.span(), &node.vis);
            visit::$traverse(self, node);
        }
    };
}

/// `visit_item_mod` override shared by [`walk_type_items`]'s and
/// [`walk_enum_variants`]'s per-file `Walker`s: push the module's name onto
/// `path` before descending into an inline `mod { .. }`, pop it back off
/// afterward, or just descend unchanged into a `mod foo;` declaration with no
/// inline body.
macro_rules! visit_item_mod_tracking_path {
    () => {
        fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
            if node.content.is_some() {
                self.path.push(node.ident.to_string());
                visit::visit_item_mod(self, node);
                self.path.pop();
            } else {
                visit::visit_item_mod(self, node);
            }
        }
    };
}

/// Joins `path` (the enclosing `mod`/`impl`/`trait` segments) and `name`
/// (the item's own identifier) into one `::`-separated qualified name, or
/// just `name` if `path` is empty — the shared naming scheme both
/// [`walk_type_items`]'s and [`walk_enum_variants`]'s per-file `Walker`s
/// apply identically.
fn joined_qualified_name(path: &[String], name: &str) -> String {
    if path.is_empty() {
        name.to_string()
    } else {
        format!("{}::{name}", path.join("::"))
    }
}

/// Visits every top-level `struct`, `enum`, `trait`, `const`, and `static` in
/// `file`, plus every associated const/type inside an `impl` block, tracking
/// the enclosing `mod`/`impl`/`trait` path the same way
/// [`crate::functions::walk_functions`] does, so the two produce consistent
/// qualified names. `pub(crate)` so [`crate::feature_matrix`] can reuse the
/// same candidate-item walk for `feature-gated-dead-code` instead of
/// reimplementing it.
pub(crate) fn walk_type_items<'ast>(
    file: &'ast syn::File,
    on_item: impl FnMut(TypeItemSite<'ast>),
) {
    struct Walker<F> {
        path: Vec<String>,
        on_item: F,
    }

    impl<F> Walker<F> {
        fn qualified_name(&self, name: &str) -> String {
            joined_qualified_name(&self.path, name)
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
        visit_item_mod_tracking_path!();

        visit_emitted_type_item!(visit_item_struct, syn::ItemStruct, visit_item_struct);
        visit_emitted_type_item!(visit_item_enum, syn::ItemEnum, visit_item_enum);

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

        visit_emitted_type_item!(visit_item_const, syn::ItemConst, visit_item_const);
        visit_emitted_type_item!(visit_item_static, syn::ItemStatic, visit_item_static);
        visit_emitted_type_item!(
            visit_impl_item_const,
            syn::ImplItemConst,
            visit_impl_item_const
        );
        visit_emitted_type_item!(
            visit_impl_item_type,
            syn::ImplItemType,
            visit_impl_item_type
        );
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
            joined_qualified_name(&self.path, name)
        }
    }

    impl<'ast, F: FnMut(EnumVariantSite<'ast>)> Visit<'ast> for Walker<F> {
        visit_item_mod_tracking_path!();

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
        path.segments
            .last()
            .is_some_and(|segment| segment.ident == name)
    }

    impl<'a> ConstructionVisitor<'a> {
        /// Marks `found` if `path` is a construction-position occurrence of
        /// `variant_name` (see this function's doc comment) — shared by
        /// `visit_expr_path` and `visit_expr_struct`, the two node kinds a
        /// construction can appear as.
        fn mark_if_constructs_variant(&mut self, path: &syn::Path) {
            if !self.in_pattern && path_ends_with(path, self.variant_name) {
                self.found = true;
            }
        }
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
            self.mark_if_constructs_variant(&node.path);
            visit::visit_expr_path(self, node);
        }

        fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
            self.mark_if_constructs_variant(&node.path);
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
/// Runs a full (non-`--no-deps`) `cargo metadata` resolve against
/// `workspace_root`'s manifest — the shared call behind [`proc_macro_exposed_crates`]
/// and [`publishable_crates`], which otherwise each ran their own
/// `MetadataCommand` identically (see [`proc_macro_exposed_crates`]'s doc
/// comment for why a full resolve, not [`crate::ingest::load`]'s `--no-deps`
/// one, is needed).
fn load_workspace_metadata(
    workspace_root: &Path,
) -> Result<cargo_metadata::Metadata, cargo_metadata::Error> {
    MetadataCommand::new()
        .manifest_path(workspace_root.join("Cargo.toml"))
        .exec()
}

fn proc_macro_exposed_crates(
    workspace_root: &Path,
) -> Result<HashSet<String>, cargo_metadata::Error> {
    let metadata = load_workspace_metadata(workspace_root)?;

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
    let metadata = load_workspace_metadata(workspace_root)?;

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

/// The `module-coupling` bucket a file's items belong to (see
/// [`MODULE_COUPLING_RULE`]): `krate_name::first_module_segment`, or
/// `krate_name::<root>` for a file at the crate root (`src/lib.rs`,
/// `src/main.rs`, or a `src/bin/*.rs` target — [`module_path_for_file`]'s own
/// `Some(String::new())` case). `None` if `module_path_for_file` itself
/// returns `None` (a source file outside `src/`, e.g. `build.rs`) — such a
/// file's items are simply excluded from `module-coupling`'s accumulation,
/// the same "not inferable, so omit" stance the rest of this module takes.
fn top_level_module_bucket(
    crate_root: &Path,
    file_path: &Path,
    krate_name: &str,
) -> Option<String> {
    let module_path = module_path_for_file(crate_root, file_path)?;
    if module_path.is_empty() {
        return Some(format!("{krate_name}::<root>"));
    }
    let top_level_segment = module_path.split("::").next().unwrap_or(&module_path);
    Some(format!("{krate_name}::{top_level_segment}"))
}

/// Byte offset and 1-based line number of `span`'s start — the shared
/// "convert an ident's proc-macro2 span into a queryable position" step
/// every per-item walk closure in this crate repeats before building a
/// [`ra_ap_ide::FilePosition`]. `pub(crate)` so [`crate::boundaries_deep`]
/// can reuse it for its own, unrelated `walk_functions` callback instead of
/// re-deriving the same two-field extraction.
pub(crate) fn offset_and_line(span: Span) -> (u32, usize) {
    (span.byte_range().start as u32, span.start().line)
}

/// Reads and parses `path` with `syn`, mapping a failure to the matching
/// [`DeadCodeError`] variant — the shared "read this file, translate a
/// missing/malformed one into a reportable error" step behind
/// [`analyze_workspace`]'s own per-file walk, [`check_enum_variant`]'s
/// re-parse of a referencing file, and (via [`for_each_parsed_file`])
/// [`crate::dead_trait_impl`]'s and [`crate::feature_matrix`]'s own
/// candidate-collection passes.
pub(crate) fn read_and_parse_file(path: &Path) -> Result<syn::File, DeadCodeError> {
    let source =
        std::fs::read_to_string(path).map_err(|err| DeadCodeError::Io(path.to_path_buf(), err))?;
    syn::parse_file(&source).map_err(|err| DeadCodeError::Parse(path.to_path_buf(), err))
}

/// [`read_and_parse_file`], pushing a failure onto `report.errors` and
/// returning `None` instead of propagating it — the shared "parse this file
/// within a loop, or skip it and move on" step behind [`analyze_workspace`]'s
/// own per-file walk and [`check_enum_variant`]'s re-parse of a referencing
/// file, both of which need to `continue` their own loop on failure rather
/// than visit an `on_file` callback the way [`for_each_parsed_file`] does.
fn parsed_file_or_report(report: &mut WorkspaceDeadCode, path: &Path) -> Option<syn::File> {
    match read_and_parse_file(path) {
        Ok(ast) => Some(ast),
        Err(err) => {
            report.errors.push(err);
            None
        }
    }
}

/// Walks every locally-reportable source file across `workspace`'s crates,
/// reading and parsing each with [`read_and_parse_file`] and calling
/// `on_file` with the result. A per-file read/parse failure is pushed onto
/// `errors` and that file is skipped — a non-fatal, reported error, not a
/// hard stop for the whole run. Shared by
/// [`crate::dead_trait_impl::collect_candidates`] and
/// [`crate::feature_matrix::collect_candidates`], which otherwise repeated
/// this exact walk verbatim.
pub(crate) fn for_each_parsed_file(
    workspace: &Workspace,
    errors: &mut Vec<DeadCodeError>,
    mut on_file: impl FnMut(&SourceFile, &syn::File),
) {
    for krate in &workspace.crates {
        for file in &krate.source_files {
            if !file.kind.is_locally_reportable() {
                continue;
            }
            match read_and_parse_file(&file.path) {
                Ok(ast) => on_file(file, &ast),
                Err(err) => errors.push(err),
            }
        }
    }
}

/// Increments `report.checked` and builds the [`ra_ap_ide::FilePosition`] for
/// `file_id`/`offset` — the shared prologue [`check_item`],
/// [`check_enum_variant`], [`check_test_only_pub`], and
/// [`check_unreachable_from_entry`] each start with.
fn checked_position(
    report: &mut WorkspaceDeadCode,
    file_id: FileId,
    offset: u32,
) -> ra_ap_ide::FilePosition {
    report.checked += 1;
    ra_ap_ide::FilePosition {
        file_id,
        offset: offset.into(),
    }
}

/// Calls [`crate::deep::referencing_files`], recording a non-fatal
/// [`DeadCodeError::Deep`] and returning `None` on failure — the shared
/// "resolve referencing files, or give up on this item" step behind
/// [`check_item`], [`check_enum_variant`], and [`check_test_only_pub`].
fn referencing_files_or_bail(
    analysis: &ra_ap_ide::Analysis,
    position: ra_ap_ide::FilePosition,
    include_tests: bool,
    report: &mut WorkspaceDeadCode,
) -> Option<HashSet<FileId>> {
    match crate::deep::referencing_files(analysis, position, include_tests) {
        Ok(referencing) => Some(referencing),
        Err(err) => {
            report.errors.push(DeadCodeError::Deep(err));
            None
        }
    }
}

/// Builds the shared [`Finding`] shape every per-item dead-code check in this
/// module produces: the same `id` format (`rule:file:qualified_name`), the
/// same [`Location`], [`Origin::Code`], and empty `caused_by`/`causes` — only
/// `rule_id`, `severity`, `evidence_class`, `evidence`, and `limitations`
/// vary per rule/call site. Shared by [`check_item`], [`check_enum_variant`],
/// [`check_test_only_pub`], and [`check_unreachable_from_entry`].
#[allow(clippy::too_many_arguments)]
fn dead_code_finding(
    rule_id: &str,
    severity: Severity,
    evidence_class: EvidenceClass,
    file: &SourceFile,
    line: usize,
    qualified_name: &str,
    evidence: serde_json::Value,
    limitations: Option<Vec<String>>,
) -> Finding {
    Finding {
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
        limitations,
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// [`check_item`]'s `crate-coupling`/`module-coupling` edge accumulation
/// (see [`CRATE_COUPLING_RULE`], [`MODULE_COUPLING_RULE`]): for every file
/// referencing this item, counts a crate-coupling edge whenever the
/// referencing crate differs from `krate_name`, and a module-coupling edge
/// whenever the item's own module (`file_id`, looked up in `module_of_file`)
/// differs from the referencing file's module — independently of each other,
/// and independently of whether the item turns out to be externally used.
fn accumulate_coupling_edges(
    referencing: &HashSet<FileId>,
    file_id: FileId,
    crate_of_file: &HashMap<FileId, &str>,
    module_of_file: &HashMap<FileId, String>,
    krate_name: &str,
    edge_counts: &mut HashMap<(String, String), u32>,
    module_edge_counts: &mut HashMap<(String, String), u32>,
) {
    for referencing_file in referencing {
        if let Some(&referencing_crate) = crate_of_file.get(referencing_file)
            && referencing_crate != krate_name
        {
            *edge_counts
                .entry((krate_name.to_string(), referencing_crate.to_string()))
                .or_insert(0) += 1;
        }
        if let (Some(owner_module), Some(referencing_module)) = (
            module_of_file.get(&file_id),
            module_of_file.get(referencing_file),
        ) && owner_module != referencing_module
        {
            *module_edge_counts
                .entry((owner_module.clone(), referencing_module.clone()))
                .or_insert(0) += 1;
        }
    }
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
    module_of_file: &HashMap<FileId, String>,
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
    edge_counts: &mut HashMap<(String, String), u32>,
    module_edge_counts: &mut HashMap<(String, String), u32>,
    report: &mut WorkspaceDeadCode,
) {
    let position = checked_position(report, file_id, offset);

    let Some(referencing) = referencing_files_or_bail(analysis, position, include_tests, report)
    else {
        return;
    };
    // Done here, over the *full* `referencing` set and before the
    // `used_externally` early exit below, so no cross-crate/cross-module
    // reference is silently dropped just because this particular item also
    // happens to be used_externally == false (unused-pub-workspace/
    // unused-pub-api still want it flagged) or == true (which returns early,
    // right after this).
    accumulate_coupling_edges(
        &referencing,
        file_id,
        crate_of_file,
        module_of_file,
        krate_name,
        edge_counts,
        module_edge_counts,
    );
    if is_used_externally(&referencing, crate_of_file, krate_name) {
        return;
    }

    let evidence = serde_json::json!({
        "tier": "deep",
        "searched_crates": searched_crates_count(crate_of_file),
        "references_found": referencing.len(),
        "root_set_size": entry_keys.len(),
        "reason": reason,
    });
    push_finding_if_unreachable(
        analysis,
        entry_keys,
        position,
        include_tests,
        proc_macro_exposed,
        krate_name,
        rule_id,
        severity,
        evidence_class,
        file,
        line,
        qualified_name,
        evidence,
        report,
    );
}

/// Whether any of `referencing`'s files belongs to a crate other than
/// `krate_name` — the shared "does something outside this item's own crate
/// use it" check both [`check_item`] and [`check_test_only_pub`] apply before
/// consulting entry-point reachability at all.
fn is_used_externally(
    referencing: &HashSet<FileId>,
    crate_of_file: &HashMap<FileId, &str>,
    krate_name: &str,
) -> bool {
    referencing.iter().any(|referencing_file| {
        crate_of_file
            .get(referencing_file)
            .is_some_and(|owner| *owner != krate_name)
    })
}

/// Number of distinct crates `crate_of_file` covers — the "how wide a view
/// did this query search" evidence figure both [`check_item`] and
/// [`check_test_only_pub`] report alongside their reachability result.
fn searched_crates_count(crate_of_file: &HashMap<FileId, &str>) -> usize {
    crate_of_file.values().copied().collect::<HashSet<&str>>().len()
}

/// Runs [`crate::reachability::is_reachable_from_entry`] and, on `Ok(false)`
/// (unreachable), pushes one [`dead_code_finding`] carrying `evidence`
/// (already assembled by the caller, since each rule's evidence shape
/// differs) plus this crate's proc-macro-expansion limitation; on `Err`,
/// records it via [`reachability_error`] instead. [`check_item`] and
/// [`check_unreachable_from_entry`] both wrap the same reachability query in
/// this exact dispatch, differing only in which rule/evidence they attach.
#[allow(clippy::too_many_arguments)]
fn push_finding_if_unreachable(
    analysis: &ra_ap_ide::Analysis,
    entry_keys: &std::collections::HashSet<(FileId, u32)>,
    position: ra_ap_ide::FilePosition,
    include_tests: bool,
    proc_macro_exposed: &HashSet<String>,
    krate_name: &str,
    rule_id: &str,
    severity: Severity,
    evidence_class: EvidenceClass,
    file: &SourceFile,
    line: usize,
    qualified_name: &str,
    evidence: serde_json::Value,
    report: &mut WorkspaceDeadCode,
) {
    match crate::reachability::is_reachable_from_entry(analysis, entry_keys, position, include_tests)
    {
        Ok(true) => {}
        Ok(false) => {
            let limitations = proc_macro_exposed
                .contains(krate_name)
                .then(|| vec!["proc_macro_expansion_disabled".to_string()]);
            report.findings.push(dead_code_finding(
                rule_id,
                severity,
                evidence_class,
                file,
                line,
                qualified_name,
                evidence,
                limitations,
            ));
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
/// one `errors` list. `pub(crate)` so [`crate::feature_matrix`] can reuse it
/// for `feature-gated-dead-code`'s own `errors` list instead of duplicating
/// the mapping.
pub(crate) fn reachability_error(err: crate::reachability::ReachabilityError) -> DeadCodeError {
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
    let position = checked_position(report, file_id, offset);

    let Some(referencing) = referencing_files_or_bail(analysis, position, include_tests, report)
    else {
        return;
    };

    let mut construction_found = false;
    for referencing_file_id in &referencing {
        let Some(path) = file_path_by_id.get(referencing_file_id) else {
            continue;
        };
        let Some(ast) = parsed_file_or_report(report, path) else {
            continue;
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
    report.findings.push(dead_code_finding(
        DEAD_ENUM_VARIANT_RULE,
        Severity::Warn,
        EvidenceClass::BoundedSemantic,
        file,
        line,
        qualified_name,
        evidence,
        None,
    ));
}

/// Calls [`crate::reachability::is_reachable_from_entry`], recording a
/// non-fatal [`reachability_error`] and returning `None` on failure — the
/// shared "check reachability, or give up on this item" step behind
/// [`check_test_only_pub`]'s two reachability queries (production, then
/// all), which otherwise repeated this exact match verbatim.
fn reachable_or_bail(
    analysis: &ra_ap_ide::Analysis,
    entry_keys: &std::collections::HashSet<(FileId, u32)>,
    position: ra_ap_ide::FilePosition,
    include_tests: bool,
    report: &mut WorkspaceDeadCode,
) -> Option<bool> {
    match crate::reachability::is_reachable_from_entry(analysis, entry_keys, position, include_tests)
    {
        Ok(reachable) => Some(reachable),
        Err(err) => {
            report.errors.push(reachability_error(err));
            None
        }
    }
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
    let position = checked_position(report, file_id, offset);

    // The cross-crate check uses the "all" search — a reference from another
    // workspace crate's test code is still evidence this item has a life
    // outside its own crate, the same disqualifying condition `check_item`
    // applies.
    let Some(referencing) = referencing_files_or_bail(analysis, position, true, report) else {
        return;
    };
    if is_used_externally(&referencing, crate_of_file, krate_name) {
        return;
    }

    let Some(production_reachable) =
        reachable_or_bail(analysis, entry_keys_production, position, false, report)
    else {
        return;
    };
    if production_reachable {
        // Reachable in production already — not test-only.
        return;
    }

    let Some(all_reachable) = reachable_or_bail(analysis, entry_keys_all, position, true, report)
    else {
        return;
    };
    if !all_reachable {
        // Unreachable even with tests counted — `unused-pub-workspace`'s/
        // `unused-pub-api`'s territory, not this rule's.
        return;
    }

    let evidence = serde_json::json!({
        "tier": "deep",
        "searched_crates": searched_crates_count(crate_of_file),
        "references_found": referencing.len(),
        "root_set_size_production": entry_keys_production.len(),
        "root_set_size_all": entry_keys_all.len(),
        "reason": "reachable only through #[cfg(test)]/test-target code in the examined \
            workspace view",
    });
    report.findings.push(dead_code_finding(
        TEST_ONLY_PUB_RULE,
        Severity::Warn,
        EvidenceClass::BoundedSemantic,
        file,
        line,
        qualified_name,
        evidence,
        None,
    ));
}

/// `check_unreachable_from_entry`'s `reason` text (see
/// [`UNREACHABLE_FROM_ENTRY_RULE`]) — matches `unused-pub-workspace`'s "no
/// reference found"-style wording pattern, adapted for a reachability-only
/// claim since this rule never checks cross-crate references at all.
const UNREACHABLE_FROM_ENTRY_REASON: &str = "not reachable from any recognized entry point \
    (fn main in a [[bin]] or [[example]] target, a #[test]/#[bench] function, or an \
    FFI/wasm-bindgen export) in the examined reachability view";

/// Checks one non-`pub` item for `unreachable-from-entry`: no cross-crate
/// reference check at all — see [`UNREACHABLE_FROM_ENTRY_RULE`]'s doc
/// comment for why that's sound for a non-`pub` item — just
/// [`crate::reachability::is_reachable_from_entry`] directly, the same
/// entry-point BFS [`check_item`] itself calls once its own cross-crate
/// check clears.
#[allow(clippy::too_many_arguments)]
fn check_unreachable_from_entry(
    analysis: &ra_ap_ide::Analysis,
    entry_keys: &std::collections::HashSet<(FileId, u32)>,
    proc_macro_exposed: &HashSet<String>,
    file: &SourceFile,
    file_id: FileId,
    krate_name: &str,
    qualified_name: &str,
    offset: u32,
    line: usize,
    include_tests: bool,
    report: &mut WorkspaceDeadCode,
) {
    let position = checked_position(report, file_id, offset);

    let evidence = serde_json::json!({
        "tier": "deep",
        "root_set_size": entry_keys.len(),
        "reason": UNREACHABLE_FROM_ENTRY_REASON,
    });
    push_finding_if_unreachable(
        analysis,
        entry_keys,
        position,
        include_tests,
        proc_macro_exposed,
        krate_name,
        UNREACHABLE_FROM_ENTRY_RULE,
        Severity::Warn,
        EvidenceClass::BoundedSemantic,
        file,
        line,
        qualified_name,
        evidence,
        report,
    );
}

/// Builds [`analyze_workspace`]'s three file-id-keyed lookup maps in one
/// pass over every workspace source file: the owning crate name, its path
/// (for `dead-enum-variant` evidence), and its `module-coupling` bucket (see
/// [`MODULE_COUPLING_RULE`], [`top_level_module_bucket`]) — so `check_item`
/// can look up both an item's own module and a referencing file's module
/// without re-deriving either per query.
fn build_file_maps<'a>(
    workspace: &'a Workspace,
    ctx: &DeepContext,
) -> Result<
    (
        HashMap<FileId, &'a str>,
        HashMap<FileId, PathBuf>,
        HashMap<FileId, String>,
    ),
    DeadCodeError,
> {
    let mut crate_of_file: HashMap<FileId, &str> = HashMap::new();
    let mut file_path_by_id: HashMap<FileId, PathBuf> = HashMap::new();
    let mut module_of_file: HashMap<FileId, String> = HashMap::new();
    for krate in &workspace.crates {
        for file in &krate.source_files {
            if let Some(file_id) = ctx.file_id(&file.path).map_err(DeadCodeError::Deep)? {
                crate_of_file.insert(file_id, krate.name.as_str());
                file_path_by_id.insert(file_id, file.path.clone());
                if let Some(bucket) = top_level_module_bucket(&krate.root, &file.path, &krate.name)
                {
                    module_of_file.insert(file_id, bucket);
                }
            }
        }
    }
    Ok((crate_of_file, file_path_by_id, module_of_file))
}

/// The "production" and "all" reachability entry-key sets [`analyze_workspace`]
/// needs — `test-only-pub` (see [`check_test_only_pub`]) needs both modes
/// regardless of `include_tests`, so both are computed unconditionally here.
fn compute_entry_key_sets(
    workspace: &Workspace,
    ctx: &DeepContext,
) -> Result<
    (
        std::collections::HashSet<(FileId, u32)>,
        std::collections::HashSet<(FileId, u32)>,
    ),
    DeadCodeError,
> {
    let entries_production = crate::reachability::entry_point_positions(workspace, ctx, false)
        .map_err(reachability_error)?;
    let entry_keys_production = crate::reachability::entry_keys_from(&entries_production);
    let entries_all = crate::reachability::entry_point_positions(workspace, ctx, true)
        .map_err(reachability_error)?;
    let entry_keys_all = crate::reachability::entry_keys_from(&entries_all);
    Ok((entry_keys_production, entry_keys_all))
}

/// The two `cargo_metadata`-backed sets [`analyze_workspace`] needs before
/// its crate loop: proc-macro-exposed crates (see [`proc_macro_exposed_crates`])
/// and publishable crates (see [`publishable_crates`]). A metadata failure on
/// either is recorded as a soft error and falls back to an empty set — for
/// `publishable`, that conservatively treats every crate as non-publishable,
/// i.e. the stricter, gating `unused-pub-workspace` rather than silently
/// downgrading a real finding to `unused-pub-api`'s `Info`/advisory-only
/// shape.
fn load_proc_macro_and_publishable_sets(
    workspace_root: &Path,
    report: &mut WorkspaceDeadCode,
) -> (HashSet<String>, HashSet<String>) {
    let proc_macro_exposed = match proc_macro_exposed_crates(workspace_root) {
        Ok(exposed) => exposed,
        Err(err) => {
            report.errors.push(DeadCodeError::Metadata(err));
            HashSet::new()
        }
    };
    let publishable = match publishable_crates(workspace_root) {
        Ok(publishable) => publishable,
        Err(err) => {
            report.errors.push(DeadCodeError::Metadata(err));
            HashSet::new()
        }
    };
    (proc_macro_exposed, publishable)
}

/// The per-file body of [`analyze_workspace`]'s crate/file loop: walks one
/// already-parsed file's functions/methods, top-level type items, and enum
/// variants, routing each `pub` site to [`check_item`]/[`check_test_only_pub`]
/// and each non-`pub` function/type-item site to [`check_unreachable_from_entry`].
#[allow(clippy::too_many_arguments)]
fn scan_file_for_dead_code(
    analysis: &ra_ap_ide::Analysis,
    crate_of_file: &HashMap<FileId, &str>,
    module_of_file: &HashMap<FileId, String>,
    file_path_by_id: &HashMap<FileId, PathBuf>,
    entry_keys: &std::collections::HashSet<(FileId, u32)>,
    entry_keys_production: &std::collections::HashSet<(FileId, u32)>,
    entry_keys_all: &std::collections::HashSet<(FileId, u32)>,
    proc_macro_exposed: &HashSet<String>,
    ast: &syn::File,
    file: &SourceFile,
    file_id: FileId,
    krate_name: &str,
    include_tests: bool,
    rule_id: &str,
    severity: Severity,
    evidence_class: EvidenceClass,
    reason: &str,
    edge_counts: &mut HashMap<(String, String), u32>,
    module_edge_counts: &mut HashMap<(String, String), u32>,
    report: &mut WorkspaceDeadCode,
) {
    walk_functions(ast, |site| {
        let (offset, line) = offset_and_line(site.ident_span);
        if let Some(syn::Visibility::Public(_)) = site.vis {
            check_item(
                analysis,
                crate_of_file,
                module_of_file,
                entry_keys,
                proc_macro_exposed,
                file,
                file_id,
                krate_name,
                &site.qualified_name,
                offset,
                line,
                include_tests,
                rule_id,
                severity,
                evidence_class,
                reason,
                edge_counts,
                module_edge_counts,
                report,
            );
            check_test_only_pub(
                analysis,
                crate_of_file,
                entry_keys_production,
                entry_keys_all,
                file,
                file_id,
                krate_name,
                &site.qualified_name,
                offset,
                line,
                report,
            );
            return;
        }
        // `site.vis == None` is a trait's default method, which has
        // no visibility of its own (see `FunctionSite::vis`'s doc
        // comment) — ambiguous whether it belongs on the `pub` or
        // non-`pub` side of this split, so it's left unchecked by
        // both, same as today.
        if let Some(syn::Visibility::Inherited | syn::Visibility::Restricted(_)) = site.vis {
            check_unreachable_from_entry(
                analysis,
                entry_keys,
                proc_macro_exposed,
                file,
                file_id,
                krate_name,
                &site.qualified_name,
                offset,
                line,
                include_tests,
                report,
            );
        }
    });

    walk_type_items(ast, |site| {
        let (offset, line) = offset_and_line(site.ident_span);
        if matches!(site.vis, syn::Visibility::Public(_)) {
            check_item(
                analysis,
                crate_of_file,
                module_of_file,
                entry_keys,
                proc_macro_exposed,
                file,
                file_id,
                krate_name,
                &site.qualified_name,
                offset,
                line,
                include_tests,
                rule_id,
                severity,
                evidence_class,
                reason,
                edge_counts,
                module_edge_counts,
                report,
            );
            check_test_only_pub(
                analysis,
                crate_of_file,
                entry_keys_production,
                entry_keys_all,
                file,
                file_id,
                krate_name,
                &site.qualified_name,
                offset,
                line,
                report,
            );
            return;
        }
        check_unreachable_from_entry(
            analysis,
            entry_keys,
            proc_macro_exposed,
            file,
            file_id,
            krate_name,
            &site.qualified_name,
            offset,
            line,
            include_tests,
            report,
        );
    });

    walk_enum_variants(ast, |site| {
        if !matches!(site.vis, syn::Visibility::Public(_)) {
            return;
        }
        check_enum_variant(
            analysis,
            file_path_by_id,
            file,
            file_id,
            &site.qualified_name,
            &site.variant_name,
            site.ident_span.byte_range().start as u32,
            site.ident_span.start().line,
            include_tests,
            report,
        );
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

    let (crate_of_file, file_path_by_id, module_of_file) = build_file_maps(workspace, &ctx)?;

    let (entry_keys_production, entry_keys_all) = compute_entry_key_sets(workspace, &ctx)?;
    let entry_keys = if include_tests {
        &entry_keys_all
    } else {
        &entry_keys_production
    };

    let mut report = WorkspaceDeadCode::default();

    // `crate-coupling`'s edge-count accumulator (see [`CRATE_COUPLING_RULE`])
    // — `(owner_crate_of_referenced_item, referencing_crate) -> count`,
    // filled in as a side effect of `check_item`'s existing per-pub-item
    // `referencing_files` query below, then folded into per-crate Ce/Ca
    // findings after the crate loop.
    let mut edge_counts: HashMap<(String, String), u32> = HashMap::new();

    // `module-coupling`'s edge-count accumulator (see
    // [`MODULE_COUPLING_RULE`]) — `(owner_module, referencing_module) ->
    // count`, filled in alongside `edge_counts` above by the same
    // `check_item` call, then folded into per-module Ce/Ca findings after
    // the crate loop.
    let mut module_edge_counts: HashMap<(String, String), u32> = HashMap::new();

    let (proc_macro_exposed, publishable) =
        load_proc_macro_and_publishable_sets(&workspace.root, &mut report);

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
            let Some(file_id) = ctx.file_id(&file.path).map_err(DeadCodeError::Deep)? else {
                // Not indexed by the loader (e.g. excluded, or the loader
                // failed to discover this target) — nothing to query.
                continue;
            };

            let Some(ast) = parsed_file_or_report(&mut report, &file.path) else {
                continue;
            };

            scan_file_for_dead_code(
                &analysis,
                &crate_of_file,
                &module_of_file,
                &file_path_by_id,
                entry_keys,
                &entry_keys_production,
                &entry_keys_all,
                &proc_macro_exposed,
                &ast,
                file,
                file_id,
                &krate.name,
                include_tests,
                rule_id,
                severity,
                evidence_class,
                reason,
                &mut edge_counts,
                &mut module_edge_counts,
                &mut report,
            );
        }
    }

    report
        .findings
        .extend(crate_coupling_findings(workspace, &edge_counts));
    report
        .findings
        .extend(module_coupling_findings(workspace, &module_edge_counts));

    Ok(report)
}

/// Folds [`analyze_workspace`]'s accumulated `edge_counts` into one
/// `crate-coupling` [`Finding`] per crate with at least one observed
/// cross-crate coupling edge (`Ca + Ce > 0`, Robert C. Martin's efferent/
/// afferent coupling counts — see [`CRATE_COUPLING_RULE`]). A crate with no
/// cross-crate coupling at all is skipped, not flagged — there is nothing to
/// report for it.
/// owner/referencer -> distinct counterpart keys, the Ca/Ce shape
/// [`afferent_efferent_sets`] returns and [`coupling_metrics`] reads from.
type CouplingSets<'a> = HashMap<&'a str, BTreeSet<&'a str>>;

/// Ca, Ce, instability, and the sorted evidence lists [`coupling_metrics`]
/// returns for one coupling key.
type CouplingMetrics<'a> = (usize, usize, f64, Vec<&'a str>, Vec<&'a str>);

/// Builds the Ca/Ce (afferent/efferent) sets `edge_counts` implies: owner ->
/// distinct referencing keys (Ca) and referencer -> distinct referenced keys
/// (Ce). `BTreeSet` for deterministic, sorted, deduped evidence lists.
/// Shared by [`crate_coupling_findings`] and [`module_coupling_findings`] —
/// keyed by crate name or module bucket string respectively, but otherwise
/// the exact same fold.
fn afferent_efferent_sets(
    edge_counts: &HashMap<(String, String), u32>,
) -> (CouplingSets<'_>, CouplingSets<'_>) {
    let mut afferent: CouplingSets<'_> = HashMap::new();
    let mut efferent: CouplingSets<'_> = HashMap::new();
    for (owner, referencer) in edge_counts.keys() {
        afferent
            .entry(owner.as_str())
            .or_default()
            .insert(referencer.as_str());
        efferent
            .entry(referencer.as_str())
            .or_default()
            .insert(owner.as_str());
    }
    (afferent, efferent)
}

/// Ca, Ce, instability (`Ce / (Ca + Ce)`), and the sorted evidence lists for
/// one coupling key — `None` if it has no coupling at all (`Ca + Ce == 0`),
/// the shared "nothing to report" skip both [`crate_coupling_findings`] and
/// [`module_coupling_findings`] apply before pushing a finding.
fn coupling_metrics<'a>(
    key: &str,
    afferent: &CouplingSets<'a>,
    efferent: &CouplingSets<'a>,
) -> Option<CouplingMetrics<'a>> {
    let afferent_set = afferent.get(key);
    let efferent_set = efferent.get(key);
    let ca = afferent_set.map_or(0, BTreeSet::len);
    let ce = efferent_set.map_or(0, BTreeSet::len);
    if ca + ce == 0 {
        return None;
    }
    let instability = ce as f64 / (ca + ce) as f64;
    let efferent_list = efferent_set
        .map(|set| set.iter().copied().collect::<Vec<_>>())
        .unwrap_or_default();
    let afferent_list = afferent_set
        .map(|set| set.iter().copied().collect::<Vec<_>>())
        .unwrap_or_default();
    Some((ca, ce, instability, efferent_list, afferent_list))
}

/// Builds the shared [`Finding`] tail both [`crate_coupling_findings`] and
/// [`module_coupling_findings`] produce once their coupling metrics are
/// computed: `Severity::Info`, `EvidenceClass::Heuristic`, `Origin::Code`,
/// no limitations, empty `caused_by`/`causes` — only the id, rule, location,
/// and evidence vary per coupling key.
fn coupling_finding(
    id: String,
    rule_id: &str,
    file: PathBuf,
    item_path: String,
    evidence: serde_json::Value,
) -> Finding {
    Finding {
        id: id.into(),
        rule: rule_id.into(),
        severity: Severity::Info,
        location: Location {
            file,
            line: OneBasedLine::FIRST,
            item_path,
        },
        evidence_class: EvidenceClass::Heuristic,
        origin: Origin::Code,
        evidence: Some(evidence),
        limitations: None,
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

fn crate_coupling_findings(
    workspace: &Workspace,
    edge_counts: &HashMap<(String, String), u32>,
) -> Vec<Finding> {
    let (afferent, efferent) = afferent_efferent_sets(edge_counts);

    let mut findings = Vec::new();
    for krate in &workspace.crates {
        let Some((ca, ce, instability, efferent_crates, afferent_crates)) =
            coupling_metrics(krate.name.as_str(), &afferent, &efferent)
        else {
            continue;
        };
        findings.push(coupling_finding(
            format!("{CRATE_COUPLING_RULE}:{}", krate.name),
            CRATE_COUPLING_RULE,
            krate.manifest_path.clone(),
            krate.name.clone(),
            serde_json::json!({
                "tier": "deep",
                "krate": krate.name,
                "efferent_coupling": ce,
                "afferent_coupling": ca,
                "instability": instability,
                "efferent_crates": efferent_crates,
                "afferent_crates": afferent_crates,
            }),
        ));
    }
    findings
}

/// Folds [`analyze_workspace`]'s accumulated `module_edge_counts` into one
/// `module-coupling` [`Finding`] per top-level module bucket with at least
/// one observed coupling edge (`Ca + Ce > 0` — see [`MODULE_COUPLING_RULE`]).
/// A module with no coupling at all is skipped, not flagged — there is
/// nothing to report for it. Mirrors [`crate_coupling_findings`]'s Ce/Ca
/// fold exactly, just keyed by module bucket string instead of crate name;
/// see [`MODULE_COUPLING_RULE`]'s doc comment for how that bucket string is
/// derived and why it's broader in scope (same-crate cross-module edges
/// count here, not just cross-crate ones).
fn module_coupling_findings(
    workspace: &Workspace,
    edge_counts: &HashMap<(String, String), u32>,
) -> Vec<Finding> {
    let (afferent, efferent) = afferent_efferent_sets(edge_counts);
    let mut modules: BTreeSet<&str> = BTreeSet::new();
    for (owner, referencer) in edge_counts.keys() {
        modules.insert(owner.as_str());
        modules.insert(referencer.as_str());
    }

    // A module bucket string is `krate_name::segment` — its leading
    // component before the first `::` is always the owning crate's name, so
    // the finding's location can point at that crate's manifest the same
    // way `crate_coupling_findings` does, rather than picking one arbitrary
    // file out of the (possibly many) files a module bucket spans.
    let manifest_path_by_crate: HashMap<&str, &Path> = workspace
        .crates
        .iter()
        .map(|krate| (krate.name.as_str(), krate.manifest_path.as_path()))
        .collect();

    let mut findings = Vec::new();
    for module in modules {
        let Some((ca, ce, instability, efferent_modules, afferent_modules)) =
            coupling_metrics(module, &afferent, &efferent)
        else {
            continue;
        };
        let krate_name = module.split("::").next().unwrap_or(module);
        let manifest_path = manifest_path_by_crate
            .get(krate_name)
            .copied()
            .unwrap_or_else(|| Path::new(""));
        findings.push(coupling_finding(
            format!("{MODULE_COUPLING_RULE}:{module}"),
            MODULE_COUPLING_RULE,
            manifest_path.to_path_buf(),
            module.to_string(),
            serde_json::json!({
                "tier": "deep",
                "module": module,
                "efferent_coupling": ce,
                "afferent_coupling": ca,
                "instability": instability,
                "efferent_modules": efferent_modules,
                "afferent_modules": afferent_modules,
            }),
        ));
    }
    findings
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
    fn a_completely_unused_private_fn_is_flagged_unreachable_from_entry() {
        // Before `unreachable-from-entry` existed, `check_item`'s `pub`-only
        // filter meant a non-`pub` item was never queried at all (see
        // `UNREACHABLE_FROM_ENTRY_RULE`'s doc comment for why that's now a
        // separate rule rather than widening `check_item`'s own scope).
        let dir = TempDir::new("dead-code-private-fn");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"fn private_and_unused() -> i32 {
    1
}
"#,
        );

        let report = analyze_workspace(&workspace, true).unwrap();

        assert_eq!(report.checked, 1);
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        let finding = &report.findings[0];
        assert_eq!(finding.rule, UNREACHABLE_FROM_ENTRY_RULE);
        assert_eq!(finding.severity, Severity::Warn);
        assert_eq!(finding.evidence_class, EvidenceClass::BoundedSemantic);
        assert_eq!(finding.location.item_path, "private_and_unused");

        let evidence = finding.evidence.as_ref().expect("evidence must be present");
        assert_eq!(evidence["tier"], "deep");
        assert!(evidence["reason"].is_string());
    }

    #[test]
    fn a_private_fn_called_from_main_is_not_flagged_unreachable_from_entry() {
        let dir = TempDir::new("dead-code-private-fn-reachable-from-main");
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
            r#"fn private_helper() -> i32 {
    1
}

pub fn call_helper() -> i32 {
    private_helper()
}
"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("src/bin/tool.rs"),
            r#"fn main() {
    dead_code_fixture::call_helper();
}
"#,
        )
        .unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.location.item_path == "private_helper"),
            "private_helper is transitively reachable from main via call_helper — must not be \
             flagged: {:?}",
            report.findings
        );
    }

    #[test]
    fn a_private_fn_called_from_a_test_is_not_flagged_unreachable_from_entry() {
        let dir = TempDir::new("dead-code-private-fn-reachable-from-test");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"fn private_helper() -> i32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test() {
        assert_eq!(private_helper(), 1);
    }
}
"#,
        );

        let report = analyze_workspace(&workspace, true).unwrap();

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.location.item_path == "private_helper"),
            "private_helper is reachable from the #[test] fn a_test — must not be flagged: {:?}",
            report.findings
        );
    }

    #[test]
    fn a_test_fn_itself_is_not_flagged_unreachable_from_entry() {
        let dir = TempDir::new("dead-code-test-fn-itself");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"#[cfg(test)]
mod tests {
    #[test]
    fn a_test() {
        assert_eq!(1, 1);
    }
}
"#,
        );

        let report = analyze_workspace(&workspace, true).unwrap();

        assert_eq!(report.checked, 1, "a_test itself must still be queried");
        assert!(
            report.findings.is_empty(),
            "a_test is itself a recognized entry point — it is trivially reachable from itself, \
             not \"unreachable from entry\": {:?}",
            report.findings
        );
    }

    #[test]
    fn a_pub_item_genuinely_unreachable_is_not_flagged_unreachable_from_entry() {
        // The non-overlap this rule promises: a `pub` item's unreachability
        // stays `unused-pub-workspace`/`unused-pub-api`/`test-only-pub`'s
        // territory (see `UNREACHABLE_FROM_ENTRY_RULE`'s doc comment).
        let dir = TempDir::new("dead-code-pub-item-not-unreachable-from-entry");
        let workspace = load_single_crate_workspace(
            &dir,
            r#"pub fn never_called() -> i32 {
    1
}
"#,
        );

        let report = analyze_workspace(&workspace, true).unwrap();

        let rules: HashSet<&str> = report
            .findings
            .iter()
            .filter(|f| f.location.item_path == "never_called")
            .map(|f| f.rule.as_str())
            .collect();
        assert!(
            !rules.contains(UNREACHABLE_FROM_ENTRY_RULE),
            "a pub item's unreachability is unused-pub-workspace/unused-pub-api's territory, not \
             unreachable-from-entry's: {:?}",
            report.findings
        );
        assert!(
            rules.contains(UNUSED_PUB_WORKSPACE_RULE) || rules.contains(UNUSED_PUB_API_RULE),
            "control: never_called must still be flagged by the pub-item rule family: {:?}",
            report.findings
        );
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
    fn a_private_struct_never_referenced_is_flagged_unreachable_from_entry() {
        // `check_item` itself still never checks a non-`pub` type item (see
        // `walk_type_items`'s `Public`-only branch above) — this is now
        // `unreachable-from-entry`'s territory instead of "unchecked".
        let dir = TempDir::new("dead-code-private-struct");
        let workspace = load_single_crate_workspace(&dir, "struct PrivateStruct;\n");

        let report = analyze_workspace(&workspace, true).unwrap();

        assert_eq!(report.checked, 1);
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        assert_eq!(report.findings[0].rule, UNREACHABLE_FROM_ENTRY_RULE);
        assert_eq!(report.findings[0].location.item_path, "PrivateStruct");
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
        let file_id = ctx.file_id(&file.path).unwrap().unwrap();
        let crate_of_file = HashMap::from([(file_id, krate.name.as_str())]);
        let module_of_file = HashMap::new();
        let entry_keys = std::collections::HashSet::new();

        // Strictly inside the body's indentation whitespace — no symbol.
        let offset = lib_source.find("    1").unwrap() as u32 + 1;

        let mut report = WorkspaceDeadCode::default();
        let proc_macro_exposed = HashSet::new();
        let mut edge_counts = HashMap::new();
        let mut module_edge_counts = HashMap::new();
        check_item(
            &analysis,
            &crate_of_file,
            &module_of_file,
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
            &mut edge_counts,
            &mut module_edge_counts,
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
    /// `helper` now carries `limitations: ["proc_macro_expansion_disabled"]`
    /// — the uncertainty is surfaced instead of hidden behind an unqualified
    /// `unused-pub-workspace` warning.
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
        assert_eq!(
            helper_finding.limitations,
            Some(vec!["proc_macro_expansion_disabled".to_string()]),
            "`core` has a direct proc-macro dependency (`macros`), so the finding must disclose \
             that proc-macro expansion was disabled instead of presenting `helper` as an \
             unqualified dead-code finding: {:?}",
            helper_finding.limitations
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
        assert_eq!(
            finding.limitations,
            Some(vec!["proc_macro_expansion_disabled".to_string()]),
            "`core` directly depends on the proc-macro crate `macros`, so the finding must \
             disclose that proc-macro expansion was disabled, even though this particular dead \
             item is unrelated to the derive: {:?}",
            finding.limitations
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
        assert!(
            finding.limitations.is_none(),
            "no proc-macro dependency anywhere in this workspace — the finding must not carry a \
             `limitations` field: {:?}",
            finding.limitations
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
    fn a_pub_fn_used_by_another_workspace_crate_is_not_flagged_test_only_pub_even_if_also_tested() {
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

    /// See `unused_pub_workspace_registry_example_still_triggers_the_rule`'s
    /// doc comment.
    #[cfg(feature = "deep")]
    #[test]
    fn unreachable_from_entry_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(UNREACHABLE_FROM_ENTRY_RULE)
            .expect("unreachable-from-entry has a registry entry")
            .example
            .expect("unreachable-from-entry has a curated example")
            .before;

        let dir = TempDir::new("dead-code-unreachable-from-entry-registry-example");
        let workspace = load_single_crate_workspace(&dir, example);

        let report = analyze_workspace(&workspace, true).unwrap();

        assert_eq!(
            report
                .findings
                .iter()
                .filter(|f| f.rule == UNREACHABLE_FROM_ENTRY_RULE)
                .count(),
            1,
            "{:?}",
            report.findings
        );
    }

    /// `crate-coupling`'s Ca/Ce shape: `core` is called by both `app` and
    /// `plugin`, so `core` should get `Ca=2` (two distinct crates reference
    /// it), `Ce=0` (it references nothing cross-crate), and an Instability
    /// near 0.0 — the low-instability shape expected of a shared, stable
    /// core crate. `app` and `plugin` each call into `core`, so each should
    /// get `Ce>=1`.
    #[cfg(feature = "deep")]
    #[test]
    fn crate_coupling_reports_ca_ce_for_a_shared_core_crate() {
        let dir = TempDir::new("dead-code-crate-coupling-core");
        write_crate(
            &dir,
            "core",
            &[],
            r#"pub fn shared_helper() -> i32 {
    1
}
"#,
        );
        write_crate(
            &dir,
            "app",
            &[("core", "../core")],
            r#"pub fn run() -> i32 {
    core::shared_helper()
}
"#,
        );
        write_crate(
            &dir,
            "plugin",
            &[("core", "../core")],
            r#"pub fn run() -> i32 {
    core::shared_helper()
}
"#,
        );
        write_workspace_manifest(&dir, &["core", "app", "plugin"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();

        let core_finding = report
            .findings
            .iter()
            .find(|f| f.rule == CRATE_COUPLING_RULE && f.location.item_path == "core")
            .unwrap_or_else(|| {
                panic!(
                    "no crate-coupling finding for `core`: {:?}",
                    report.findings
                )
            });
        let evidence = core_finding
            .evidence
            .as_ref()
            .expect("evidence must be present");
        assert_eq!(evidence["afferent_coupling"], serde_json::json!(2));
        assert_eq!(evidence["efferent_coupling"], serde_json::json!(0));
        assert_eq!(evidence["instability"], serde_json::json!(0.0));
        assert_eq!(
            evidence["afferent_crates"],
            serde_json::json!(["app", "plugin"])
        );

        for consumer in ["app", "plugin"] {
            let consumer_finding = report
                .findings
                .iter()
                .find(|f| f.rule == CRATE_COUPLING_RULE && f.location.item_path == consumer)
                .unwrap_or_else(|| {
                    panic!(
                        "no crate-coupling finding for `{consumer}`: {:?}",
                        report.findings
                    )
                });
            let evidence = consumer_finding
                .evidence
                .as_ref()
                .expect("evidence must be present");
            assert!(
                evidence["efferent_coupling"].as_u64().unwrap() >= 1,
                "`{consumer}` calls into `core` — must have Ce >= 1: {evidence:?}"
            );
        }
    }

    /// A crate with zero cross-crate coupling (nothing calls it, it calls
    /// nothing) must not be flagged — there is nothing to report.
    #[cfg(feature = "deep")]
    #[test]
    fn crate_coupling_skips_a_fully_isolated_crate() {
        let dir = TempDir::new("dead-code-crate-coupling-isolated");
        write_crate(
            &dir,
            "isolated",
            &[],
            r#"pub fn never_referenced_elsewhere() -> i32 {
    1
}
"#,
        );
        write_workspace_manifest(&dir, &["isolated"]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == CRATE_COUPLING_RULE),
            "a crate with no cross-crate coupling at all must not be flagged: {:?}",
            report.findings
        );
    }

    /// Splits a `// crate: <name>` marked multi-crate source (see the
    /// `crate-coupling` registry example in `rule_registry.rs`, and
    /// `api_surface_deep.rs`'s identical convention for `re-export-chain`)
    /// into `(name, source)` pairs, in encounter order.
    #[cfg(feature = "deep")]
    fn split_marked_crates(source: &str) -> Vec<(&str, String)> {
        let mut result: Vec<(&str, String)> = Vec::new();
        for line in source.lines() {
            if let Some(name) = line.strip_prefix("// crate: ") {
                result.push((name, String::new()));
            } else if let Some(entry) = result.last_mut() {
                entry.1.push_str(line);
                entry.1.push('\n');
            }
        }
        result
    }

    /// The registry's curated `example.before` for this rule (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// this is what keeps a landing-page-facing example from silently
    /// drifting away from what judge actually flags.
    #[cfg(feature = "deep")]
    #[test]
    fn crate_coupling_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(CRATE_COUPLING_RULE)
            .expect("crate-coupling has a registry entry")
            .example
            .expect("crate-coupling has a curated example")
            .before;

        let crates = split_marked_crates(example);
        assert_eq!(crates.len(), 3, "expected 3 marked crates: {crates:?}");
        let crate0 = crates[0].0;
        let crate1 = crates[1].0;
        let crate2 = crates[2].0;
        let dep = format!("../{crate0}");

        let dir = TempDir::new("dead-code-crate-coupling-registry-example");
        write_crate(&dir, crate0, &[], &crates[0].1);
        write_crate(&dir, crate1, &[(crate0, &dep)], &crates[1].1);
        write_crate(&dir, crate2, &[(crate0, &dep)], &crates[2].1);
        write_workspace_manifest(&dir, &[crate0, crate1, crate2]);

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();

        assert_eq!(
            report
                .findings
                .iter()
                .filter(|f| f.rule == CRATE_COUPLING_RULE)
                .count(),
            3,
            "{:?}",
            report.findings
        );
    }

    /// Writes an extra source file into a [`load_single_crate_workspace`]-
    /// style single-crate fixture's `src/` directory — `module-coupling`'s
    /// tests need several top-level modules within one crate, unlike
    /// `crate-coupling`'s multi-crate `write_crate`/`write_workspace_manifest`
    /// fixtures.
    #[cfg(feature = "deep")]
    fn write_single_crate_module(dir: &TempDir, relative_path: &str, source: &str) {
        let path = dir.join("src").join(relative_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, source).unwrap();
    }

    /// `module-coupling`'s Ca/Ce shape, the module-granularity counterpart
    /// to `crate_coupling_reports_ca_ce_for_a_shared_core_crate`: within one
    /// crate, `core` is called by both `consumer_a` and `consumer_b`, so it
    /// should get `Ca=2` (two distinct modules reference it), `Ce=0` (it
    /// references nothing cross-module itself), and an Instability near
    /// 0.0. `consumer_a` and `consumer_b` each call into `core`, so each
    /// should get `Ce>=1`.
    #[cfg(feature = "deep")]
    #[test]
    fn module_coupling_reports_ca_ce_for_a_shared_core_module() {
        let dir = TempDir::new("dead-code-module-coupling-core");
        let workspace = load_single_crate_workspace(
            &dir,
            "pub mod core_mod;\npub mod consumer_a;\npub mod consumer_b;\n",
        );
        write_single_crate_module(
            &dir,
            "core_mod.rs",
            r#"pub fn shared_helper() -> i32 {
    1
}
"#,
        );
        write_single_crate_module(
            &dir,
            "consumer_a.rs",
            r#"pub fn run() -> i32 {
    crate::core_mod::shared_helper()
}
"#,
        );
        write_single_crate_module(
            &dir,
            "consumer_b.rs",
            r#"pub fn run() -> i32 {
    crate::core_mod::shared_helper()
}
"#,
        );

        let workspace = crate::ingest::load(Some(&workspace.root.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();

        let krate_name = &workspace.crates[0].name;
        let core_module = format!("{krate_name}::core_mod");
        let core_finding = report
            .findings
            .iter()
            .find(|f| f.rule == MODULE_COUPLING_RULE && f.location.item_path == core_module)
            .unwrap_or_else(|| {
                panic!(
                    "no module-coupling finding for `{core_module}`: {:?}",
                    report.findings
                )
            });
        let evidence = core_finding
            .evidence
            .as_ref()
            .expect("evidence must be present");
        assert_eq!(evidence["afferent_coupling"], serde_json::json!(2));
        assert_eq!(evidence["efferent_coupling"], serde_json::json!(0));
        assert_eq!(evidence["instability"], serde_json::json!(0.0));
        assert_eq!(
            evidence["afferent_modules"],
            serde_json::json!([
                format!("{krate_name}::consumer_a"),
                format!("{krate_name}::consumer_b"),
            ])
        );

        for consumer_module in [
            format!("{krate_name}::consumer_a"),
            format!("{krate_name}::consumer_b"),
        ] {
            let consumer_finding = report
                .findings
                .iter()
                .find(|f| f.rule == MODULE_COUPLING_RULE && f.location.item_path == consumer_module)
                .unwrap_or_else(|| {
                    panic!(
                        "no module-coupling finding for `{consumer_module}`: {:?}",
                        report.findings
                    )
                });
            let evidence = consumer_finding
                .evidence
                .as_ref()
                .expect("evidence must be present");
            assert!(
                evidence["efferent_coupling"].as_u64().unwrap() >= 1,
                "`{consumer_module}` calls into `core_mod` — must have Ce >= 1: {evidence:?}"
            );
        }
    }

    /// A module with zero cross-module coupling (nothing calls it, it calls
    /// nothing) must not be flagged — there is nothing to report, the
    /// module-granularity counterpart to
    /// `crate_coupling_skips_a_fully_isolated_crate`.
    #[cfg(feature = "deep")]
    #[test]
    fn module_coupling_skips_a_module_with_no_cross_module_coupling() {
        let dir = TempDir::new("dead-code-module-coupling-isolated");
        let workspace = load_single_crate_workspace(&dir, "pub mod isolated_mod;\n");
        write_single_crate_module(
            &dir,
            "isolated_mod.rs",
            r#"pub fn never_referenced_elsewhere() -> i32 {
    1
}
"#,
        );

        let workspace = crate::ingest::load(Some(&workspace.root.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule == MODULE_COUPLING_RULE),
            "a module with no cross-module coupling at all must not be flagged: {:?}",
            report.findings
        );
    }

    /// Splits a `// file: <name>.rs` marked multi-module source (see the
    /// `module-coupling` registry example in `rule_registry.rs`) into
    /// `(file_name, source)` pairs, in encounter order — the single-crate
    /// counterpart to `split_marked_crates`.
    #[cfg(feature = "deep")]
    fn split_marked_files(source: &str) -> Vec<(&str, String)> {
        let mut result: Vec<(&str, String)> = Vec::new();
        for line in source.lines() {
            if let Some(name) = line.strip_prefix("// file: ") {
                result.push((name, String::new()));
            } else if let Some(entry) = result.last_mut() {
                entry.1.push_str(line);
                entry.1.push('\n');
            }
        }
        result
    }

    /// The registry's curated `example.before` for this rule (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// this is what keeps a landing-page-facing example from silently
    /// drifting away from what judge actually flags.
    #[cfg(feature = "deep")]
    #[test]
    fn module_coupling_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(MODULE_COUPLING_RULE)
            .expect("module-coupling has a registry entry")
            .example
            .expect("module-coupling has a curated example")
            .before;

        let files = split_marked_files(example);
        assert_eq!(files.len(), 3, "expected 3 marked files: {files:?}");

        let dir = TempDir::new("dead-code-module-coupling-registry-example");
        let mod_declarations: String = files
            .iter()
            .map(|(name, _)| {
                let mod_name = name.strip_suffix(".rs").expect("marked file ends in .rs");
                format!("pub mod {mod_name};\n")
            })
            .collect();
        let workspace = load_single_crate_workspace(&dir, &mod_declarations);
        for (name, source) in &files {
            write_single_crate_module(&dir, name, source);
        }

        let workspace = crate::ingest::load(Some(&workspace.root.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace, true).unwrap();

        assert_eq!(
            report
                .findings
                .iter()
                .filter(|f| f.rule == MODULE_COUPLING_RULE)
                .count(),
            3,
            "{:?}",
            report.findings
        );
    }
}
