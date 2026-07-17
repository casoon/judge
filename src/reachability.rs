//! `--why-live`: the shortest evidenced path from a recognized entry point to
//! a given item (see todo.md §3.A "Reachability-Modi", §14.2 P1). Requires
//! the `deep` feature.
//!
//! **Entry-point scope, documented rather than hidden:** only `fn main` in a
//! `[[bin]]`/`[[example]]` target counts as a root for now (todo.md §3.A's
//! full Entry-Point-Modell also includes `#[no_mangle]`, `#[wasm_bindgen]`,
//! registration macros, etc. — not attempted here). A workspace-internal
//! crate's own `pub` API is deliberately *not* treated as an automatic root
//! — that mirrors [`crate::dead_code`]'s same simplification (every crate
//! counts as workspace-internal, not published), so the two stay consistent:
//! something [`crate::dead_code`] calls dead is never reported "live" here
//! just because it's `pub`.

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;

use ra_ap_ide::{CallHierarchyConfig, FilePosition, RaFixtureConfig};

use crate::deep::{DeepContext, DeepError, FileId};
use crate::functions::walk_functions;
use crate::ingest::{EntryPointKind, Workspace};

#[derive(Debug)]
pub enum ReachabilityError {
    Deep(DeepError),
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, syn::Error),
    /// No function with this qualified name was found anywhere in the
    /// workspace (see [`crate::functions::walk_functions`]'s naming scheme).
    UnknownItem(String),
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

/// Finds every `fn main` in a `[[bin]]`/`[[example]]` target — the
/// production entry points this module recognizes (see module docs).
fn entry_point_positions(
    workspace: &Workspace,
    ctx: &DeepContext,
) -> Result<Vec<(String, FilePosition)>, ReachabilityError> {
    let mut entries = Vec::new();
    for krate in &workspace.crates {
        for entry in &krate.entry_points {
            if !matches!(entry.kind, EntryPointKind::Bin | EntryPointKind::Example) {
                continue;
            }
            let Some(file_id) = ctx.file_id(&entry.path) else {
                continue;
            };
            let source = std::fs::read_to_string(&entry.path)
                .map_err(|err| ReachabilityError::Io(entry.path.clone(), err))?;
            let ast = syn::parse_file(&source)
                .map_err(|err| ReachabilityError::Parse(entry.path.clone(), err))?;

            walk_functions(&ast, |site| {
                if site.qualified_name == "main" {
                    let offset = site.ident_span.byte_range().start as u32;
                    entries.push((
                        format!("{}::main", entry.name),
                        FilePosition {
                            file_id,
                            offset: offset.into(),
                        },
                    ));
                }
            });
        }
    }
    Ok(entries)
}

/// Resolves a qualified name (as produced by
/// [`crate::functions::walk_functions`]) to its position, by parsing every
/// authored source file until a match is found. The first match in
/// workspace-crate-sorted, file-sorted order wins if the name isn't unique —
/// a deterministic, if arbitrary, tiebreak.
fn find_item_position(
    workspace: &Workspace,
    ctx: &DeepContext,
    item_path: &str,
) -> Result<FilePosition, ReachabilityError> {
    for krate in &workspace.crates {
        for file in &krate.source_files {
            let Some(file_id) = ctx.file_id(&file.path) else {
                continue;
            };
            let source = std::fs::read_to_string(&file.path)
                .map_err(|err| ReachabilityError::Io(file.path.clone(), err))?;
            let ast = syn::parse_file(&source)
                .map_err(|err| ReachabilityError::Parse(file.path.clone(), err))?;

            let mut found = None;
            walk_functions(&ast, |site| {
                if found.is_none() && site.qualified_name == item_path {
                    let offset = site.ident_span.byte_range().start as u32;
                    found = Some(offset);
                }
            });
            if let Some(offset) = found {
                return Ok(FilePosition {
                    file_id,
                    offset: offset.into(),
                });
            }
        }
    }
    Err(ReachabilityError::UnknownItem(item_path.to_string()))
}

/// A stable, sortable identity for a `FilePosition`, used to dedupe BFS
/// visits and to give callers found in the same step a deterministic order.
fn position_key(position: FilePosition) -> (FileId, u32) {
    (position.file_id, position.offset.into())
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

    let entries = entry_point_positions(workspace, &ctx)?;
    let entry_keys: HashSet<(FileId, u32)> =
        entries.iter().map(|(_, position)| position_key(*position)).collect();

    let target = find_item_position(workspace, &ctx, item_path)?;
    let (target_file, target_line) = describe_position(workspace, &ctx, target);

    if entry_keys.contains(&position_key(target)) {
        return Ok(WhyLive::Path(vec![PathStep {
            qualified_name: item_path.to_string(),
            file: target_file,
            line: target_line,
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
    }];
    let mut queue: VecDeque<(FilePosition, Vec<PathStep>)> =
        VecDeque::from([(target, initial_path)]);

    while let Some((position, path_so_far)) = queue.pop_front() {
        let callers = analysis
            .incoming_calls(&config, position)
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
                (caller_position, call_item.target.name.as_str().to_string())
            })
            .collect();
        // Deterministic tiebreak: sort by (file id, offset) before visiting.
        callers.sort_by_key(|(position, _)| position_key(*position));

        for (caller_position, caller_name) in callers {
            let key = position_key(caller_position);
            if !visited.insert(key) {
                continue;
            }

            let (caller_file, caller_line) = describe_position(workspace, &ctx, caller_position);
            let mut new_path = path_so_far.clone();
            new_path.push(PathStep {
                qualified_name: caller_name,
                file: caller_file,
                line: caller_line,
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
}
