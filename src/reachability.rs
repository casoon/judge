//! `--why-live`: the shortest evidenced path from a recognized entry point to
//! a given item (see todo.md §3.A "Reachability-Modi", §14.2 P1). Requires
//! the `deep` feature.
//!
//! **Entry-point scope, documented rather than hidden:** recognized roots are
//! `fn main` in a `[[bin]]`/`[[example]]` target, `#[test]`-like functions
//! (any attribute whose path ends in `test`, so `#[tokio::test]` and
//! `#[async_std::test]` count too) and `#[bench]` functions when
//! `include_tests` is set, and `#[no_mangle]`/`#[export_name]`/
//! `#[wasm_bindgen]`-attributed functions unconditionally (external,
//! non-Rust callers — C ABI or JS via wasm-bindgen). Generic registration
//! macros (`inventory::submit!`, `linkme::distributed_slice`, `ctor`, …) are
//! *not* recognized — there's no fixed attribute or call shape to key off
//! generically, and guessing at specific crate names would be arbitrary. A
//! workspace-internal crate's own `pub` API is deliberately *not* treated as
//! an automatic root — that mirrors [`crate::dead_code`]'s same
//! simplification (every crate counts as workspace-internal, not
//! published), so the two stay consistent: something [`crate::dead_code`]
//! calls dead is never reported "live" here just because it's `pub`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

use ra_ap_hir::{InFile, Semantics};
use ra_ap_ide::{Analysis, CallHierarchyConfig, FilePosition, FileRange, RaFixtureConfig, RootDatabase};
use ra_ap_syntax::{AstNode, TextRange, ast};

use crate::deep::{DeepContext, DeepError, FileId};
use crate::functions::walk_functions;
use crate::ingest::{EntryPointKind, SourceKind, Workspace};

#[derive(Debug)]
pub enum ReachabilityError {
    Deep(DeepError),
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, syn::Error),
    /// No function with this qualified name was found anywhere in the
    /// workspace (see [`crate::functions::walk_functions`]'s naming scheme).
    UnknownItem(String),
    /// More than one function matches this qualified name — `walk_functions`
    /// tracks the `mod`/`impl`/`trait` path *within* a file, but not the
    /// file's own module path, so two unrelated files each defining, say, a
    /// top-level `pub fn helper` produce the same qualified name. Prefix
    /// `item_path` with `<crate-name>::` to narrow the search to one crate;
    /// if that's still ambiguous, there's no further disambiguation today.
    AmbiguousItem(String, Vec<(PathBuf, usize)>),
}

impl std::fmt::Display for ReachabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deep(err) => write!(f, "{err}"),
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
            Self::UnknownItem(item_path) => {
                write!(f, "no function named `{item_path}` found in the workspace")
            }
            Self::AmbiguousItem(item_path, candidates) => {
                writeln!(
                    f,
                    "`{item_path}` matches more than one function — prefix it with `<crate-name>::` to disambiguate:"
                )?;
                for (index, (path, line)) in candidates.iter().enumerate() {
                    if index > 0 {
                        writeln!(f)?;
                    }
                    write!(f, "  {}:{line}", path.display())?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ReachabilityError {}

/// One hop in a `--why-live` path: the caller that leads one step closer to
/// a recognized entry point.
#[derive(Debug, Clone)]
pub struct PathStep {
    pub qualified_name: String,
    pub file: PathBuf,
    pub line: usize,
    /// How the *edge into* this step dispatches — `None` for the first step
    /// (the target item itself has no incoming edge in its own path).
    pub kind: Option<CallKind>,
}

/// The dispatch mechanism behind one call edge in a `--why-live` path —
/// evidence for how much a caller can trust the edge (see todo.md §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    /// A direct call to a statically known function, tuple-struct, or
    /// tuple-enum-variant constructor.
    Static,
    /// Dispatch through a `dyn Trait` object, a stored function pointer, or
    /// a closure value — the concrete callee isn't fixed at this call site.
    Dynamic,
    /// The call site sits inside a macro invocation's input (a
    /// `macro_rules!` call), or its containing item has a derive/attribute
    /// macro applied.
    Macro,
    /// The call site is in a source file classified as generated (see
    /// [`crate::ingest::SourceKind`]) — code provenance is the more useful
    /// signal here, ahead of dispatch mechanism.
    Generated,
    /// The reference wasn't found inside a call or method-call expression at
    /// all (e.g. the function's name used as a bare value, `let f =
    /// callee;`), or Deep Tier syntax resolution didn't find a matching
    /// node — honestly unclassifiable rather than guessed.
    Unknown,
}

impl CallKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Dynamic => "dynamic",
            Self::Macro => "macro",
            Self::Generated => "generated",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for CallKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classifies one call-site range (from `CallItem::ranges`) by dispatch
/// mechanism. Requires dropping from the `Analysis` facade down to
/// `hir::Semantics` directly — `Analysis` has no call-site resolution of its
/// own (see todo.md §14.2 P1's Kantenart-Klassifizierung note).
///
/// Known imprecision, documented rather than hidden: a method call resolved
/// through a generic type parameter (`fn foo<T: Trait>(x: T) { x.method() }`)
/// reports `Static` here — genuinely static in the sense that the call site
/// itself doesn't go through a vtable, even though the chosen implementation
/// varies per monomorphized instantiation. Only receivers whose *type* is an
/// actual trait object (`dyn Trait`) count as `Dynamic`.
fn classify_call_kind(
    sema: &Semantics<'_, RootDatabase>,
    db: &RootDatabase,
    file_id: FileId,
    range: TextRange,
) -> CallKind {
    let source_file = sema.parse_guess_edition(file_id);
    let syntax = source_file.syntax();

    let Some(token) = syntax.token_at_offset(range.start()).find(|token| token.text_range() == range)
    else {
        return CallKind::Unknown;
    };

    let editioned_file_id = sema.attach_first_edition(file_id);
    if sema.is_inside_macro_call(InFile::new(editioned_file_id.into(), &token)) {
        return CallKind::Macro;
    }

    let Some(name_ref) = token.parent().and_then(ast::NameRef::cast) else {
        return CallKind::Unknown;
    };

    for ancestor in name_ref.syntax().ancestors() {
        if let Some(method_call) = ast::MethodCallExpr::cast(ancestor.clone()) {
            let is_method_name = method_call
                .name_ref()
                .is_some_and(|name_ref| name_ref.syntax().text_range() == range);
            if !is_method_name {
                return CallKind::Unknown;
            }
            let is_dynamic = method_call
                .receiver()
                .and_then(|receiver| sema.type_of_expr(&receiver))
                .is_some_and(|info| info.original.strip_references().as_dyn_trait().is_some());
            return if is_dynamic { CallKind::Dynamic } else { CallKind::Static };
        }

        if let Some(call_expr) = ast::CallExpr::cast(ancestor.clone()) {
            let is_our_callee = call_expr
                .expr()
                .is_some_and(|callee| callee.syntax().text_range().contains_range(range));
            if !is_our_callee {
                return CallKind::Unknown;
            }
            return call_expr
                .expr()
                .and_then(|callee| sema.type_of_expr(&callee))
                .and_then(|info| info.original.as_callable(db))
                .map_or(CallKind::Unknown, |callable| match callable.kind() {
                    ra_ap_hir::CallableKind::Function(_)
                    | ra_ap_hir::CallableKind::TupleStruct(_)
                    | ra_ap_hir::CallableKind::TupleEnumVariant(_) => CallKind::Static,
                    ra_ap_hir::CallableKind::Closure(_)
                    | ra_ap_hir::CallableKind::FnPtr
                    | ra_ap_hir::CallableKind::FnImpl(_) => CallKind::Dynamic,
                });
        }
    }

    CallKind::Unknown
}

/// The result of asking "why is this item live" — either a path to a
/// recognized entry point (the evidence), or a statement that none was
/// found within the Deep Tier's visibility (see the module docs' entry-point
/// scope caveat — "not reachable" here means "not reachable from a `fn main`
/// this run recognized", not an absolute claim).
#[derive(Debug)]
pub enum WhyLive {
    /// Ordered from the target item to the entry point that reaches it.
    Path(Vec<PathStep>),
    NotReachable,
}

/// Whether any of `attrs` has a path whose last segment is `ident` — matches
/// both a bare attribute (`#[test]`) and a path-qualified one
/// (`#[tokio::test]`, `#[wasm_bindgen::prelude::wasm_bindgen]`).
pub(crate) fn has_attr_ending_in(attrs: &[syn::Attribute], ident: &str) -> bool {
    attrs
        .iter()
        .any(|attr| attr.path().segments.last().is_some_and(|segment| segment.ident == ident))
}

/// Finds every recognized entry point (see module docs): `fn main` in a
/// `[[bin]]`/`[[example]]` target, `#[test]`/`#[bench]`-like functions when
/// `include_tests` is set, and `#[no_mangle]`/`#[export_name]`/
/// `#[wasm_bindgen]`-attributed functions unconditionally. Also used by
/// [`crate::dead_code`] to treat an item reachable from its own crate's
/// entry point as live, even with no cross-crate reference — a
/// single-crate workspace has no "other crate" to ever reference anything,
/// which would otherwise make `unused-pub-workspace` flag the entire public
/// API of the common case (see todo.md §14.2 P1).
pub(crate) fn entry_point_positions(
    workspace: &Workspace,
    ctx: &DeepContext,
    include_tests: bool,
) -> Result<Vec<(String, FilePosition)>, ReachabilityError> {
    let mut entries = Vec::new();
    for krate in &workspace.crates {
        let bin_or_example_name: HashMap<FileId, &str> = krate
            .entry_points
            .iter()
            .filter(|entry| matches!(entry.kind, EntryPointKind::Bin | EntryPointKind::Example))
            .filter_map(|entry| Some((ctx.file_id(&entry.path)?, entry.name.as_str())))
            .collect();

        for file in &krate.source_files {
            let Some(file_id) = ctx.file_id(&file.path) else {
                continue;
            };
            let source = std::fs::read_to_string(&file.path)
                .map_err(|err| ReachabilityError::Io(file.path.clone(), err))?;
            let ast = syn::parse_file(&source)
                .map_err(|err| ReachabilityError::Parse(file.path.clone(), err))?;

            walk_functions(&ast, |site| {
                let offset = site.ident_span.byte_range().start as u32;
                let position = FilePosition {
                    file_id,
                    offset: offset.into(),
                };

                if let Some(entry_name) = bin_or_example_name.get(&file_id)
                    && site.qualified_name == "main"
                {
                    entries.push((format!("{entry_name}::main"), position));
                    return;
                }

                let recognized = (include_tests
                    && (has_attr_ending_in(site.attrs, "test")
                        || has_attr_ending_in(site.attrs, "bench")))
                    || has_attr_ending_in(site.attrs, "no_mangle")
                    || has_attr_ending_in(site.attrs, "export_name")
                    || has_attr_ending_in(site.attrs, "wasm_bindgen");
                if recognized {
                    entries.push((format!("{}::{}", krate.name, site.qualified_name), position));
                }
            });
        }
    }
    Ok(entries)
}

/// Resolves a qualified name (as produced by
/// [`crate::functions::walk_functions`]) to its position, by parsing every
/// authored source file and collecting every match. `walk_functions` doesn't
/// track a file's own module path (only the `mod`/`impl`/`trait` path
/// *within* it), so the same qualified name can legitimately come from two
/// unrelated files — rather than silently picking one, that's reported as
/// [`ReachabilityError::AmbiguousItem`] with every match, so the caller can
/// narrow down with a `<crate-name>::` prefix (checked first, against
/// `item_path`'s leading segment).
fn find_item_position(
    workspace: &Workspace,
    ctx: &DeepContext,
    item_path: &str,
) -> Result<FilePosition, ReachabilityError> {
    let (crates, name) = match item_path.split_once("::") {
        Some((prefix, rest)) if workspace.crates.iter().any(|krate| krate.name == prefix) => {
            let crates: Vec<_> = workspace.crates.iter().filter(|krate| krate.name == prefix).collect();
            (crates, rest)
        }
        _ => (workspace.crates.iter().collect(), item_path),
    };

    let mut matches: Vec<(FilePosition, PathBuf, usize)> = Vec::new();
    for krate in crates {
        for file in &krate.source_files {
            let Some(file_id) = ctx.file_id(&file.path) else {
                continue;
            };
            let source = std::fs::read_to_string(&file.path)
                .map_err(|err| ReachabilityError::Io(file.path.clone(), err))?;
            let ast = syn::parse_file(&source)
                .map_err(|err| ReachabilityError::Parse(file.path.clone(), err))?;

            walk_functions(&ast, |site| {
                if site.qualified_name == name {
                    let offset = site.ident_span.byte_range().start as u32;
                    matches.push((
                        FilePosition {
                            file_id,
                            offset: offset.into(),
                        },
                        file.path.clone(),
                        site.ident_span.start().line,
                    ));
                }
            });
        }
    }

    matches.sort_by(|(_, path_a, line_a), (_, path_b, line_b)| (path_a, line_a).cmp(&(path_b, line_b)));
    match matches.len() {
        0 => Err(ReachabilityError::UnknownItem(item_path.to_string())),
        1 => Ok(matches.into_iter().next().unwrap().0),
        _ => Err(ReachabilityError::AmbiguousItem(
            item_path.to_string(),
            matches.into_iter().map(|(_, path, line)| (path, line)).collect(),
        )),
    }
}

/// A stable, sortable identity for a `FilePosition`, used to dedupe BFS
/// visits and to give callers found in the same step a deterministic order.
pub(crate) fn position_key(position: FilePosition) -> (FileId, u32) {
    (position.file_id, position.offset.into())
}

/// Collects `position`'s callers via `incoming_calls`, resolved to a
/// `FilePosition` at each caller's focus (or full) range, sorted by
/// `(FileId, offset)` for a deterministic visitation order. Shared by
/// [`why_live`] and [`is_reachable_from_entry`]. The call-site ranges are
/// carried along too (also sorted) — only [`why_live`] uses them, to
/// classify the edge; `is_reachable_from_entry`'s boolean-only search
/// ignores them.
fn deterministic_callers(
    analysis: &Analysis,
    config: &CallHierarchyConfig<'_>,
    position: FilePosition,
) -> Result<Vec<(FilePosition, String, Vec<FileRange>)>, ReachabilityError> {
    let callers = analysis
        .incoming_calls(config, position)
        .map_err(|err| ReachabilityError::Deep(DeepError::Cancelled(format!("{err:?}"))))?
        .unwrap_or_default();

    let mut callers: Vec<_> = callers
        .into_iter()
        .map(|call_item| {
            let focus = call_item.target.focus_range.unwrap_or(call_item.target.full_range);
            let caller_position = FilePosition {
                file_id: call_item.target.file_id,
                offset: focus.start(),
            };
            let mut ranges = call_item.ranges;
            ranges.sort_by_key(|range| (range.file_id, range.range.start()));
            (caller_position, call_item.target.name.as_str().to_string(), ranges)
        })
        .collect();
    callers.sort_by_key(|(position, _, _)| position_key(*position));
    Ok(callers)
}

/// Whether `target` is reachable from any recognized entry point (see module
/// docs) — the same reverse-BFS as [`why_live`], but without building the
/// human-readable path, for use in a hot loop over many candidate items
/// (see [`crate::dead_code`]). `entry_keys` is `entry_point_positions`'
/// output, pre-converted with [`position_key`] — computed once by the
/// caller and reused across every item, since it never changes within one
/// analysis run.
pub(crate) fn is_reachable_from_entry(
    analysis: &Analysis,
    entry_keys: &std::collections::HashSet<(FileId, u32)>,
    target: FilePosition,
    include_tests: bool,
) -> Result<bool, ReachabilityError> {
    if entry_keys.contains(&position_key(target)) {
        return Ok(true);
    }

    let config = CallHierarchyConfig {
        exclude_tests: !include_tests,
        ra_fixture: RaFixtureConfig::default(),
    };

    let mut visited = HashSet::from([position_key(target)]);
    let mut queue = VecDeque::from([target]);

    while let Some(position) = queue.pop_front() {
        for (caller_position, _name, _ranges) in deterministic_callers(analysis, &config, position)? {
            let key = position_key(caller_position);
            if entry_keys.contains(&key) {
                return Ok(true);
            }
            if visited.insert(key) {
                queue.push_back(caller_position);
            }
        }
    }

    Ok(false)
}

/// Explains why `item_path` is (or isn't) reachable: the shortest call chain
/// from a recognized entry point (see module docs), found via a reverse
/// breadth-first search over `incoming_calls` — starting at the target and
/// walking callers until one is itself an entry point, which guarantees the
/// first entry point found is at minimum hop-distance.
pub fn why_live(
    workspace: &Workspace,
    item_path: &str,
    include_tests: bool,
) -> Result<WhyLive, ReachabilityError> {
    let ctx = DeepContext::load(&workspace.root).map_err(ReachabilityError::Deep)?;
    let analysis = ctx.analysis();
    let db = ctx.raw_database();
    let sema = Semantics::new(db);

    let file_source_kind: HashMap<FileId, SourceKind> = workspace
        .crates
        .iter()
        .flat_map(|krate| &krate.source_files)
        .filter_map(|file| Some((ctx.file_id(&file.path)?, file.kind)))
        .collect();

    let entries = entry_point_positions(workspace, &ctx, include_tests)?;
    let entry_keys: HashSet<(FileId, u32)> =
        entries.iter().map(|(_, position)| position_key(*position)).collect();

    let target = find_item_position(workspace, &ctx, item_path)?;
    let (target_file, target_line) = describe_position(workspace, &ctx, target);

    if entry_keys.contains(&position_key(target)) {
        return Ok(WhyLive::Path(vec![PathStep {
            qualified_name: item_path.to_string(),
            file: target_file,
            line: target_line,
            kind: None,
        }]));
    }

    let config = CallHierarchyConfig {
        exclude_tests: !include_tests,
        ra_fixture: RaFixtureConfig::default(),
    };

    let mut visited = HashSet::from([position_key(target)]);
    let initial_path = vec![PathStep {
        qualified_name: item_path.to_string(),
        file: target_file,
        line: target_line,
        kind: None,
    }];
    let mut queue: VecDeque<(FilePosition, Vec<PathStep>)> =
        VecDeque::from([(target, initial_path)]);

    while let Some((position, path_so_far)) = queue.pop_front() {
        let callers = deterministic_callers(&analysis, &config, position)?;

        for (caller_position, caller_name, ranges) in callers {
            let key = position_key(caller_position);
            if !visited.insert(key) {
                continue;
            }

            let kind = if file_source_kind.get(&caller_position.file_id) == Some(&SourceKind::Generated)
            {
                CallKind::Generated
            } else if let Some(call_site) = ranges.first() {
                classify_call_kind(&sema, db, call_site.file_id, call_site.range)
            } else {
                CallKind::Unknown
            };

            let (caller_file, caller_line) = describe_position(workspace, &ctx, caller_position);
            let mut new_path = path_so_far.clone();
            new_path.push(PathStep {
                qualified_name: caller_name,
                file: caller_file,
                line: caller_line,
                kind: Some(kind),
            });

            if entry_keys.contains(&key) {
                return Ok(WhyLive::Path(new_path));
            }

            queue.push_back((caller_position, new_path));
        }
    }

    Ok(WhyLive::NotReachable)
}

/// Best-effort mapping from a `FilePosition` back to the workspace source
/// file it came from, and the 1-based line at its offset — for display
/// purposes only, computed by re-reading the file rather than threading a
/// semantic line index through the whole search.
fn describe_position(workspace: &Workspace, ctx: &DeepContext, position: FilePosition) -> (PathBuf, usize) {
    for krate in &workspace.crates {
        for file in &krate.source_files {
            if ctx.file_id(&file.path) != Some(position.file_id) {
                continue;
            }
            let line = std::fs::read_to_string(&file.path)
                .ok()
                .map(|source| {
                    let offset = usize::from(position.offset).min(source.len());
                    source[..offset].matches('\n').count() + 1
                })
                .unwrap_or(0);
            return (file.path.clone(), line);
        }
    }
    (PathBuf::from("<unknown>"), 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    fn load_bin_workspace(dir: &TempDir, lib_source: &str, bin_source: &str) -> Workspace {
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "why-live-fixture"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src/bin")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), lib_source).unwrap();
        std::fs::write(dir.join("src/bin/tool.rs"), bin_source).unwrap();

        crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap()
    }

    #[test]
    fn finds_a_path_from_main_through_an_intermediate_call() {
        let dir = TempDir::new("why-live-reachable");
        let workspace = load_bin_workspace(
            &dir,
            r#"pub fn deep_helper() -> i32 {
    1
}

pub fn middle() -> i32 {
    deep_helper()
}
"#,
            r#"fn main() {
    why_live_fixture::middle();
}
"#,
        );

        let result = why_live(&workspace, "deep_helper", true).unwrap();
        let WhyLive::Path(path) = result else {
            panic!("expected a path, got NotReachable");
        };

        let names: Vec<_> = path.iter().map(|step| step.qualified_name.as_str()).collect();
        assert_eq!(names.first(), Some(&"deep_helper"));
        assert!(names.contains(&"middle"));
        assert_eq!(names.last(), Some(&"main"));

        assert_eq!(path[0].kind, None, "the target's own step has no incoming edge");
        assert!(
            path[1..].iter().all(|step| step.kind == Some(CallKind::Static)),
            "every call in this fixture is a direct static call: {:?}",
            path.iter().map(|s| s.kind).collect::<Vec<_>>()
        );
    }

    #[test]
    fn reports_not_reachable_for_truly_dead_code() {
        let dir = TempDir::new("why-live-dead");
        let workspace = load_bin_workspace(
            &dir,
            r#"pub fn never_called() -> i32 {
    1
}
"#,
            r#"fn main() {}
"#,
        );

        let result = why_live(&workspace, "never_called", true).unwrap();
        assert!(matches!(result, WhyLive::NotReachable));
    }

    #[test]
    fn unknown_item_path_is_an_error() {
        let dir = TempDir::new("why-live-unknown");
        let workspace = load_bin_workspace(&dir, "", "fn main() {}\n");

        let err = why_live(&workspace, "does_not_exist", true).unwrap_err();
        assert!(matches!(err, ReachabilityError::UnknownItem(_)));
    }

    #[test]
    fn a_test_function_is_a_recognized_entry_point_when_include_tests_is_set() {
        let dir = TempDir::new("why-live-test-entry");
        let workspace = load_bin_workspace(
            &dir,
            r#"pub fn helper() -> i32 {
    1
}

#[test]
fn a_test() {
    helper();
}
"#,
            "fn main() {}\n",
        );

        let result = why_live(&workspace, "helper", true).unwrap();
        let WhyLive::Path(path) = result else {
            panic!("expected a path via the test function, got NotReachable");
        };
        assert_eq!(
            path.last().map(|step| step.qualified_name.as_str()),
            Some("a_test")
        );

        let result = why_live(&workspace, "helper", false).unwrap();
        assert!(
            matches!(result, WhyLive::NotReachable),
            "a #[test] function must not count as an entry point in production-only mode"
        );
    }

    #[test]
    fn a_no_mangle_function_is_an_entry_point_regardless_of_include_tests() {
        let dir = TempDir::new("why-live-no-mangle-entry");
        let workspace = load_bin_workspace(
            &dir,
            r#"pub fn helper() -> i32 {
    1
}

#[no_mangle]
pub extern "C" fn exported() -> i32 {
    helper()
}
"#,
            "fn main() {}\n",
        );

        let result = why_live(&workspace, "helper", false).unwrap();
        let WhyLive::Path(path) = result else {
            panic!("expected a path via the #[no_mangle] export, got NotReachable");
        };
        assert_eq!(
            path.last().map(|step| step.qualified_name.as_str()),
            Some("exported")
        );
    }

    #[test]
    fn a_call_through_a_dyn_trait_object_is_classified_as_dynamic() {
        let dir = TempDir::new("why-live-dyn-dispatch");
        let workspace = load_bin_workspace(
            &dir,
            r#"pub trait Greet {
    fn hi(&self) -> i32 {
        1
    }
}

pub struct Impl;

// Doesn't override `hi` — the call below dispatches to the trait's own
// default method, so `Greet::hi`'s definition is exactly what a `dyn Greet`
// method call resolves to (an overriding impl method would instead be a
// distinct, statically-unreachable-from-here definition).
impl Greet for Impl {}

pub fn dispatch(g: &dyn Greet) -> i32 {
    g.hi()
}
"#,
            r#"fn main() {
    why_live_fixture::dispatch(&why_live_fixture::Impl);
}
"#,
        );

        let result = why_live(&workspace, "Greet::hi", true).unwrap();
        let WhyLive::Path(path) = result else {
            panic!("expected a path, got NotReachable");
        };

        let dispatch_step = path
            .iter()
            .find(|step| step.qualified_name == "dispatch")
            .expect("dispatch must appear in the path");
        assert_eq!(dispatch_step.kind, Some(CallKind::Dynamic));

        let main_step = path
            .iter()
            .find(|step| step.qualified_name == "main")
            .expect("main must appear in the path");
        assert_eq!(
            main_step.kind,
            Some(CallKind::Static),
            "`dispatch(...)` itself is called directly, not through a trait object"
        );
    }

    #[test]
    fn a_call_inside_a_macro_invocation_is_classified_as_macro() {
        let dir = TempDir::new("why-live-macro-call");
        let workspace = load_bin_workspace(
            &dir,
            r#"macro_rules! call_it {
    ($func:ident) => {
        $func()
    };
}

pub fn helper() -> i32 {
    1
}

pub fn caller() -> i32 {
    call_it!(helper)
}
"#,
            r#"fn main() {
    why_live_fixture::caller();
}
"#,
        );

        let result = why_live(&workspace, "helper", true).unwrap();
        let WhyLive::Path(path) = result else {
            panic!("expected a path, got NotReachable");
        };

        let caller_step = path
            .iter()
            .find(|step| step.qualified_name == "caller")
            .expect("caller must appear in the path");
        assert_eq!(caller_step.kind, Some(CallKind::Macro));
    }

    #[test]
    fn a_call_in_a_generated_file_is_classified_as_generated() {
        let dir = TempDir::new("why-live-generated-call");
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "why-live-fixture"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src/bin")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            "pub mod generated;\n\npub fn helper() -> i32 {\n    1\n}\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("src/bin/tool.rs"),
            "fn main() {\n    why_live_fixture::generated::from_generated();\n}\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("src/generated.rs"),
            "// @generated\npub fn from_generated() -> i32 {\n    crate::helper()\n}\n",
        )
        .unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let result = why_live(&workspace, "helper", true).unwrap();
        let WhyLive::Path(path) = result else {
            panic!("expected a path via the generated file, got NotReachable");
        };
        let generated_step = path
            .iter()
            .find(|step| step.qualified_name == "from_generated")
            .expect("from_generated must appear in the path");
        assert_eq!(generated_step.kind, Some(CallKind::Generated));
    }

    #[test]
    fn an_item_path_matching_two_files_is_reported_as_ambiguous() {
        // `walk_functions` tracks the `mod`/`impl`/`trait` path *within* a
        // file, not the file's own module path — two unrelated files each
        // defining a same-named top-level `pub fn` collide.
        let dir = TempDir::new("why-live-ambiguous");
        let workspace = load_bin_workspace(
            &dir,
            "pub fn helper() -> i32 {\n    1\n}\n",
            "pub fn helper() -> i32 {\n    2\n}\n\nfn main() {}\n",
        );

        let err = why_live(&workspace, "helper", true).unwrap_err();
        let ReachabilityError::AmbiguousItem(item, candidates) = err else {
            panic!("expected AmbiguousItem, got {err:?}");
        };
        assert_eq!(item, "helper");
        assert_eq!(candidates.len(), 2);
    }

    fn write_crate_with_helper(dir: &TempDir, name: &str, return_value: i32) {
        std::fs::create_dir_all(dir.join(name).join("src")).unwrap();
        std::fs::write(
            dir.join(name).join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
        )
        .unwrap();
        std::fs::write(
            dir.join(name).join("src/lib.rs"),
            format!("pub fn helper() -> i32 {{\n    {return_value}\n}}\n"),
        )
        .unwrap();
    }

    #[test]
    fn a_crate_name_prefix_disambiguates_an_item_path_shared_across_crates() {
        let dir = TempDir::new("why-live-crate-prefix");
        write_crate_with_helper(&dir, "crate_a", 1);
        write_crate_with_helper(&dir, "crate_b", 2);
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"[workspace]
members = ["crate_a", "crate_b"]
resolver = "2"
"#,
        )
        .unwrap();

        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();

        let err = why_live(&workspace, "helper", true).unwrap_err();
        assert!(matches!(err, ReachabilityError::AmbiguousItem(_, _)));

        let result = why_live(&workspace, "crate_a::helper", true).unwrap();
        assert!(
            matches!(result, WhyLive::NotReachable),
            "crate-prefixed lookup must resolve uniquely instead of erroring"
        );
    }
}
