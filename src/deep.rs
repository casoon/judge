//! Deep Tier: semantic analysis via `ra_ap_ide`/`ra_ap_load-cargo` (see
//! todo.md §2.1). Gated behind the `deep` feature — a default (Fast Tier)
//! build never compiles or links rust-analyzer.
//!
//! This module is deliberately just the *loading* and *reference-counting*
//! primitives. It does not yet build the full production/tests/all
//! reachability graph or `unused-pub-workspace` detector (see todo.md §14.2
//! P1) — those are the next step, once this foundation is proven correct
//! against a real workspace.
//!
//! The `ra_ap_*` crates are rust-analyzer's own internals, republished as
//! libraries — the API is undocumented for external use and version-pinned
//! (`=0.0.342`) for exactly that reason (see todo.md §11 "ra_ap_*-Wartungslast").

use std::path::Path;

use ra_ap_ide::{Analysis, AnalysisHost, FilePosition, FindAllRefsConfig, RaFixtureConfig};
use ra_ap_load_cargo::{LoadCargoConfig, ProcMacroServerChoice};
use ra_ap_project_model::CargoConfig;
use ra_ap_vfs::{AbsPathBuf, Vfs, VfsPath};

pub use ra_ap_ide::FileId;

#[derive(Debug)]
pub enum DeepError {
    /// The workspace failed to load (manifest discovery, `cargo metadata`,
    /// or build-script execution failed inside `ra_ap_load-cargo`).
    Load(String),
    /// A semantic query was canceled — normally only happens if the
    /// underlying database was mutated concurrently, which this module
    /// never does after `load`, so in practice this indicates an internal
    /// rust-analyzer panic recovery, not a normal condition to retry.
    Cancelled(String),
}

impl std::fmt::Display for DeepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Load(msg) => write!(f, "failed to load workspace for deep analysis: {msg}"),
            Self::Cancelled(msg) => write!(f, "semantic query canceled: {msg}"),
        }
    }
}

impl std::error::Error for DeepError {}

/// A loaded workspace, ready for semantic queries. Building this runs a full
/// `cargo metadata`-equivalent workspace load and crate-graph construction —
/// seconds to minutes depending on workspace size (see todo.md §2.1's Deep
/// Tier cost estimate), unlike the Fast Tier's milliseconds.
pub struct DeepContext {
    host: AnalysisHost,
    vfs: Vfs,
}

impl DeepContext {
    /// Loads `workspace_root` (a directory containing a `Cargo.toml`) into a
    /// fresh in-memory analysis database. No proc-macro server and no build
    /// script execution: both are real fidelity trade-offs (macro-generated
    /// references and `OUT_DIR` code won't be visible), accepted for now to
    /// keep the first working version simple — see todo.md §3.A's own
    /// "im Zweifel nicht melden" stance on proc-macro blind spots.
    pub fn load(workspace_root: &Path) -> Result<Self, DeepError> {
        let cargo_config = CargoConfig::default();
        let load_config = LoadCargoConfig {
            load_out_dirs_from_check: false,
            with_proc_macro_server: ProcMacroServerChoice::None,
            prefill_caches: false,
            num_worker_threads: 1,
            proc_macro_processes: 0,
        };

        let (db, vfs, _proc_macro_server) = ra_ap_load_cargo::load_workspace_at(
            workspace_root,
            &cargo_config,
            &load_config,
            &|_progress| {},
        )
        .map_err(|err| DeepError::Load(format!("{err:#}")))?;

        Ok(Self {
            host: AnalysisHost::with_database(db),
            vfs,
        })
    }

    /// A read-only snapshot for running semantic queries against.
    pub fn analysis(&self) -> Analysis {
        self.host.analysis()
    }

    /// The raw database, for callers that need `hir::Semantics` directly —
    /// `Analysis`'s facade doesn't expose the lower-level HIR APIs needed for
    /// call-edge classification (see [`crate::reachability::CallKind`]).
    pub fn raw_database(&self) -> &ra_ap_ide::RootDatabase {
        self.host.raw_database()
    }

    /// Resolves an absolute file path to the `FileId` the loader assigned it,
    /// if the file was actually indexed (e.g. not excluded, and part of a
    /// crate the loader discovered).
    pub fn file_id(&self, path: &Path) -> Option<FileId> {
        let abs_path = AbsPathBuf::assert_utf8(path.to_path_buf());
        let vfs_path = VfsPath::from(abs_path);
        self.vfs.file_id(&vfs_path).map(|(file_id, _excluded)| file_id)
    }
}

/// Runs `find_all_refs` at `position` with a consistent config, shared by
/// [`reference_count`] and [`referencing_files`]. `include_tests` mirrors
/// todo.md §3.A's "getrennte Graphen für production, tests und all": `false`
/// computes production-only reachability (test-only usages don't count),
/// `true` counts every usage.
fn find_refs(
    analysis: &Analysis,
    position: FilePosition,
    include_tests: bool,
) -> Result<Vec<ra_ap_ide::ReferenceSearchResult>, DeepError> {
    let config = FindAllRefsConfig {
        search_scope: None,
        ra_fixture: RaFixtureConfig::default(),
        exclude_imports: false,
        exclude_tests: !include_tests,
    };
    let results = analysis
        .find_all_refs(position, &config)
        .map_err(|err| DeepError::Cancelled(format!("{err:?}")))?;
    Ok(results.unwrap_or_default())
}

/// Counts genuine (non-declaration) references to the item at `position`,
/// across the whole loaded workspace crate graph. `0` means the item is
/// unreferenced anywhere the Deep Tier could see (see the fidelity
/// trade-offs on [`DeepContext::load`]).
pub fn reference_count(
    analysis: &Analysis,
    position: FilePosition,
    include_tests: bool,
) -> Result<usize, DeepError> {
    let results = find_refs(analysis, position, include_tests)?;
    Ok(results
        .iter()
        .flat_map(|result| result.references.values())
        .map(Vec::len)
        .sum())
}

/// The set of files that contain at least one genuine reference to the item
/// at `position` — the basis for cross-crate usage checks like
/// `unused-pub-workspace` (see [`crate::dead_code`]): map each file back to
/// its owning crate, and check whether any of them differs from the item's
/// own defining crate.
pub fn referencing_files(
    analysis: &Analysis,
    position: FilePosition,
    include_tests: bool,
) -> Result<std::collections::HashSet<FileId>, DeepError> {
    let results = find_refs(analysis, position, include_tests)?;
    Ok(results
        .iter()
        .flat_map(|result| result.references.keys().copied())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    /// Writes a tiny real crate with one referenced and one dead `pub fn`,
    /// loads it through the Deep Tier, and proves `find_all_refs` actually
    /// distinguishes the two — the load-bearing assumption every detector
    /// built on top of this module depends on.
    #[test]
    fn reference_count_distinguishes_used_from_dead_pub_items() {
        let dir = TempDir::new("deep-reference-count");
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "deep-fixture"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        let lib_source = r#"pub fn used() -> i32 {
    1
}

pub fn dead() -> i32 {
    2
}

pub fn caller() -> i32 {
    used()
}
"#;
        std::fs::write(dir.join("src/lib.rs"), lib_source).unwrap();

        let ctx = DeepContext::load(&dir).expect("deep tier should load a trivial crate");
        let analysis = ctx.analysis();
        let file_id = ctx
            .file_id(&dir.join("src/lib.rs"))
            .expect("lib.rs should be indexed by the vfs");

        // Byte offset of the `used` identifier in `pub fn used`.
        let used_offset = lib_source.find("used").unwrap() as u32;
        // Byte offset of the `dead` identifier in `pub fn dead`.
        let dead_offset = lib_source.find("dead").unwrap() as u32;

        let used_refs = reference_count(
            &analysis,
            FilePosition {
                file_id,
                offset: used_offset.into(),
            },
            true,
        )
        .unwrap();
        let dead_refs = reference_count(
            &analysis,
            FilePosition {
                file_id,
                offset: dead_offset.into(),
            },
            true,
        )
        .unwrap();

        assert_eq!(dead_refs, 0, "`dead` has no callers and must show 0 references");
        assert_eq!(used_refs, 1, "`used` is called once, from `caller`");
    }
}
