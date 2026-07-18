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

use std::path::{Path, PathBuf};

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
    /// The queried position did not resolve to a symbol at all (whitespace,
    /// a comment, or `cfg`-inactive code, say) — rust-analyzer answered
    /// `None`, not an empty result set. Kept distinct from a resolved
    /// symbol with zero references: only the latter may mean "no
    /// references"; treating this as an empty set would let "symbol not
    /// resolvable" masquerade as dead code (see todo.md §15.1).
    UnresolvedSymbol(String),
    /// A path could not be converted into the absolute UTF-8 form the
    /// analysis vfs requires (it was relative, or not valid UTF-8). The
    /// panicking `AbsPathBuf::assert_utf8` conversion used to make this a
    /// library panic (see todo.md §15.2); now it is a propagatable error.
    InvalidPath(PathBuf),
}

impl std::fmt::Display for DeepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Load(msg) => write!(f, "failed to load workspace for deep analysis: {msg}"),
            Self::Cancelled(msg) => write!(f, "semantic query canceled: {msg}"),
            Self::UnresolvedSymbol(position) => write!(
                f,
                "semantic query at {position} did not resolve to a symbol — not the same as a \
                 symbol with zero references"
            ),
            Self::InvalidPath(path) => write!(
                f,
                "path is not absolute UTF-8 and cannot be mapped into the analysis vfs: {}",
                path.display()
            ),
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
    ///
    /// `sysroot: Some(RustLibSource::Discover)` is load-bearing, not
    /// cosmetic: `CargoConfig::default()` leaves `sysroot: None`, which
    /// `ra_ap_project_model` treats as "load no standard library at all"
    /// (`Sysroot::empty()`), not "auto-detect". Without a sysroot, `std`
    /// traits like `Iterator` and `Fn`/`FnMut` are unresolvable, so any
    /// inference that has to flow *through* them comes back `{unknown}` —
    /// concretely, the parameter type of an unannotated closure passed to
    /// `Iterator::filter`/`.any()`/etc. (inferred from `Iterator::filter`'s
    /// own `FnMut` bound) can't be determined, which makes any method call
    /// inside that closure (e.g. `file.kind.is_locally_reportable()` inside
    /// `.filter(|file| ...)`) invisible to `find_all_refs`/goto-definition,
    /// while a plain function taking the same type by value/reference
    /// resolves fine. Free-function call resolution is unaffected because it
    /// never needs type inference at all (path-based name resolution), which
    /// is why this blind spot was only caught by `unused-pub-workspace`
    /// dogfooding against real iterator-heavy code, not by the free-function
    /// only fixture below.
    ///
    /// `set_test: true` is the other half of the same fix, not independent:
    /// once a real sysroot resolves `cfg` options for real (instead of the
    /// empty/absent set `Sysroot::empty()` implies), `cfg(test)` correctly
    /// evaluates to `false` for a normal (non-`cargo test`) load — which
    /// would silently make every `#[test]`-attributed function and anything
    /// gated by an explicit `#[cfg(test)]` (e.g. `#[cfg(test)] mod tests`)
    /// invisible to analysis, breaking `include_tests: true` call resolution
    /// (`crate::reachability::why_live`'s and `is_reachable_from_entry`'s
    /// own `incoming_calls`-based BFS). `set_test: true` keeps `#[test]`
    /// code visible regardless, matching what a normal IDE session expects.
    pub fn load(workspace_root: &Path) -> Result<Self, DeepError> {
        let cargo_config = CargoConfig {
            sysroot: Some(ra_ap_project_model::RustLibSource::Discover),
            set_test: true,
            ..CargoConfig::default()
        };
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
    ///
    /// A path that is not absolute UTF-8 (see [`validated_utf8_abs`]) cannot
    /// name a vfs file at all and comes back as `None` — the same conservative
    /// "skip this file" answer as "not indexed", never a panic.
    pub fn file_id(&self, path: &Path) -> Option<FileId> {
        let abs_path = validated_utf8_abs(path).ok()?;
        let vfs_path = VfsPath::from(abs_path);
        self.vfs
            .file_id(&vfs_path)
            .map(|(file_id, _excluded)| file_id)
    }
}

/// Fallibly converts `path` into the absolute UTF-8 form the analysis vfs
/// requires. This is the non-panicking replacement for
/// `AbsPathBuf::assert_utf8`, which panics on exactly these two conditions
/// (relative path, non-UTF-8 path) — both come back as
/// [`DeepError::InvalidPath`] instead (todo.md §15.2). In practice every path
/// reaching the Deep Tier comes from `crate::ingest` (`cargo metadata` targets
/// and a walk rooted at each absolute manifest directory), so it is always
/// absolute — this boundary exists so a caller-constructed path can never
/// panic the library.
pub(crate) fn validated_utf8_abs(path: &Path) -> Result<AbsPathBuf, DeepError> {
    if path.is_absolute() && path.to_str().is_some() {
        Ok(AbsPathBuf::assert_utf8(path.to_path_buf()))
    } else {
        Err(DeepError::InvalidPath(path.to_path_buf()))
    }
}

/// Runs `find_all_refs` at `position` with a consistent config, shared by
/// [`reference_count`] and [`referencing_files`]. `include_tests` mirrors
/// todo.md §3.A's "getrennte Graphen für production, tests und all": `false`
/// computes production-only reachability (test-only usages don't count),
/// `true` counts every usage.
///
/// Three-state, not two: `find_all_refs` answering `None` means the position
/// didn't resolve to a symbol at all, and comes back as
/// [`DeepError::UnresolvedSymbol`] — only a `Some` result (possibly empty)
/// may mean "no references".
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
    analysis
        .find_all_refs(position, &config)
        .map_err(|err| DeepError::Cancelled(format!("{err:?}")))?
        .ok_or_else(|| DeepError::UnresolvedSymbol(describe_position(position)))
}

/// The best identification of a `FilePosition` available without a
/// `DeepContext` (queries only carry an `Analysis`): the vfs-assigned file id
/// plus the byte offset. Used by [`DeepError::UnresolvedSymbol`].
pub(crate) fn describe_position(position: FilePosition) -> String {
    format!(
        "{:?}, byte offset {}",
        position.file_id,
        u32::from(position.offset)
    )
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

        assert_eq!(
            dead_refs, 0,
            "`dead` has no callers and must show 0 references"
        );
        assert_eq!(used_refs, 1, "`used` is called once, from `caller`");

        // Piggybacked on the already-loaded (expensive) context: a relative
        // path used to panic inside `AbsPathBuf::assert_utf8` and must now be
        // the same conservative `None` as "not indexed" (todo.md §15.2).
        assert_eq!(
            ctx.file_id(Path::new("src/lib.rs")),
            None,
            "a relative path names no vfs file and must be None, not a panic"
        );
    }

    /// A relative path must come back as [`DeepError::InvalidPath`] from the
    /// conversion boundary — the panic-free half of todo.md §15.2. Tested
    /// directly against the conversion function: `analyze_workspace` itself
    /// never constructs such paths (ingest walks absolute manifest
    /// directories), so no integration path can reach this case.
    #[test]
    fn a_relative_path_is_an_invalid_path_error_not_a_panic() {
        let err = validated_utf8_abs(Path::new("src/lib.rs")).unwrap_err();
        assert!(
            matches!(&err, DeepError::InvalidPath(path) if path == Path::new("src/lib.rs")),
            "expected InvalidPath carrying the offending path, got: {err:?}"
        );
    }

    /// Same boundary, other panic condition: a non-UTF-8 path (constructible
    /// from raw bytes on unix) must be [`DeepError::InvalidPath`], not a
    /// panic.
    #[cfg(unix)]
    #[test]
    fn a_non_utf8_path_is_an_invalid_path_error_not_a_panic() {
        use std::os::unix::ffi::OsStrExt;

        let non_utf8 = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/\xff-not-utf8.rs"));
        assert!(
            non_utf8.is_absolute() && non_utf8.to_str().is_none(),
            "fixture must isolate the UTF-8 condition from the absoluteness condition"
        );
        let err = validated_utf8_abs(non_utf8).unwrap_err();
        assert!(
            matches!(&err, DeepError::InvalidPath(path) if path == non_utf8),
            "expected InvalidPath carrying the offending path, got: {err:?}"
        );
    }

    /// Same load-bearing assumption as
    /// [`reference_count_distinguishes_used_from_dead_pub_items`], but for a
    /// *method* referenced from another file through an unannotated closure
    /// passed to a `std` iterator adaptor (`file.kind.is_locally_reportable()`
    /// inside `.filter(|file| ...)`) — the exact shape that undercounted to
    /// zero before `DeepContext::load` set an explicit `sysroot` (see the
    /// doc comment on `load`). A free-function-only fixture can't catch this
    /// class of bug because free-function call resolution never needs type
    /// inference; this one specifically exercises the loading config, not
    /// just the reference-counting logic.
    #[test]
    fn reference_count_distinguishes_used_from_dead_pub_items_for_methods_too() {
        let dir = TempDir::new("deep-reference-count-methods");
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
        std::fs::write(
            dir.join("src/lib.rs"),
            r#"pub mod a;
pub mod b;
"#,
        )
        .unwrap();
        let a_source = r#"#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Authored,
    Generated,
}

impl SourceKind {
    pub const fn used(self) -> bool {
        matches!(self, Self::Authored)
    }

    pub const fn dead(self) -> bool {
        matches!(self, Self::Generated)
    }
}

pub struct SourceFile {
    pub kind: SourceKind,
}
"#;
        std::fs::write(dir.join("src/a.rs"), a_source).unwrap();
        std::fs::write(
            dir.join("src/b.rs"),
            r#"use crate::a::SourceFile;

pub fn count_used(files: &[SourceFile]) -> usize {
    files.iter().filter(|file| file.kind.used()).count()
}
"#,
        )
        .unwrap();

        let ctx = DeepContext::load(&dir).expect("deep tier should load a trivial crate");
        let analysis = ctx.analysis();
        let file_id = ctx
            .file_id(&dir.join("src/a.rs"))
            .expect("a.rs should be indexed by the vfs");

        // Byte offset of the `used` identifier in `pub const fn used`.
        let used_offset = a_source.find("used").unwrap() as u32;
        // Byte offset of the `dead` identifier in `pub const fn dead`.
        let dead_offset = a_source.find("dead").unwrap() as u32;

        let used_refs = referencing_files(
            &analysis,
            FilePosition {
                file_id,
                offset: used_offset.into(),
            },
            true,
        )
        .unwrap();
        let dead_refs = referencing_files(
            &analysis,
            FilePosition {
                file_id,
                offset: dead_offset.into(),
            },
            true,
        )
        .unwrap();

        assert_eq!(
            dead_refs.len(),
            0,
            "`dead` has no callers and must show 0 referencing files"
        );
        assert_eq!(
            used_refs.len(),
            1,
            "`used` is called once from b.rs, through an unannotated closure passed to \
             `Iterator::filter` — the shape that undercounted to zero without an explicit sysroot"
        );
    }

    /// A position that doesn't name a symbol (whitespace between items, the
    /// inside of a comment) must come back as
    /// [`DeepError::UnresolvedSymbol`], never as a resolved-but-empty
    /// result — `Ok(0)` here is exactly what would let "symbol not
    /// resolvable" turn into a dead-code finding downstream (todo.md §15.1).
    #[test]
    fn a_position_not_on_a_symbol_is_an_unresolved_error_not_zero_references() {
        let dir = TempDir::new("deep-unresolved-position");
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
        let lib_source = r#"// a comment, not a symbol
pub fn item() -> i32 {
    1
}
"#;
        std::fs::write(dir.join("src/lib.rs"), lib_source).unwrap();

        let ctx = DeepContext::load(&dir).expect("deep tier should load a trivial crate");
        let analysis = ctx.analysis();
        let file_id = ctx
            .file_id(&dir.join("src/lib.rs"))
            .expect("lib.rs should be indexed by the vfs");

        // Strictly inside the leading comment's text.
        let comment_offset = lib_source.find("comment").unwrap() as u32;
        // Strictly inside the body's indentation whitespace (not on a token
        // boundary, where rust-analyzer would pick an adjacent token).
        let whitespace_offset = lib_source.find("    1").unwrap() as u32 + 1;

        for offset in [comment_offset, whitespace_offset] {
            let position = FilePosition {
                file_id,
                offset: offset.into(),
            };
            let count_err = reference_count(&analysis, position, true).unwrap_err();
            assert!(
                matches!(count_err, DeepError::UnresolvedSymbol(_)),
                "offset {offset} names no symbol and must be UnresolvedSymbol, got: {count_err:?}"
            );
            let files_err = referencing_files(&analysis, position, true).unwrap_err();
            assert!(
                matches!(files_err, DeepError::UnresolvedSymbol(_)),
                "offset {offset} names no symbol and must be UnresolvedSymbol, got: {files_err:?}"
            );
        }

        // The control: a real identifier with zero references stays a
        // successfully resolved empty result, not an error.
        let item_offset = lib_source.find("item").unwrap() as u32;
        let refs = reference_count(
            &analysis,
            FilePosition {
                file_id,
                offset: item_offset.into(),
            },
            true,
        )
        .unwrap();
        assert_eq!(refs, 0, "`item` resolves fine and simply has no references");
    }

    /// `set_test: true` is the other half of the load-bearing loading
    /// config, alongside `sysroot`: once a real sysroot resolves `cfg`
    /// options for real, `cfg(test)` correctly evaluates to `false` for a
    /// normal (non-`cargo test`) load — which would silently hide every
    /// `#[test]`-attributed function (and anything gated by an explicit
    /// `#[cfg(test)]`, e.g. `#[cfg(test)] mod tests { ... }`) from analysis,
    /// making calls originating inside test code invisible to
    /// `find_all_refs`/`incoming_calls` alike. `set_test: true` tells the
    /// loader to treat `#[test]` items as active regardless — see the doc
    /// comment on `load`. This guards the `include_tests: true` half of
    /// [`reference_count`]/[`referencing_files`], which callers like
    /// `crate::reachability::why_live`'s own test suite otherwise rely on
    /// silently.
    #[test]
    fn reference_count_sees_a_call_originating_inside_cfg_test_code() {
        let dir = TempDir::new("deep-reference-count-cfg-test");
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
        let lib_source = r#"pub fn helper() -> i32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test() {
        helper();
    }
}
"#;
        std::fs::write(dir.join("src/lib.rs"), lib_source).unwrap();

        let ctx = DeepContext::load(&dir).expect("deep tier should load a trivial crate");
        let analysis = ctx.analysis();
        let file_id = ctx
            .file_id(&dir.join("src/lib.rs"))
            .expect("lib.rs should be indexed by the vfs");
        let helper_offset = lib_source.find("helper").unwrap() as u32;
        let position = FilePosition {
            file_id,
            offset: helper_offset.into(),
        };

        let with_tests = reference_count(&analysis, position, true).unwrap();
        let without_tests = reference_count(&analysis, position, false).unwrap();

        assert_eq!(
            with_tests, 1,
            "the call inside `#[cfg(test)] mod tests` containing `#[test] fn a_test` must be \
             visible when include_tests is true"
        );
        assert_eq!(
            without_tests, 0,
            "the same call must not count in production-only mode"
        );
    }
}
