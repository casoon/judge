//! Ingest layer: discovers workspace crates, source files, and entry points via `cargo metadata`.

use std::path::{Path, PathBuf};

use cargo_metadata::{MetadataCommand, TargetKind};

/// A crate discovered in the workspace.
#[derive(Debug)]
pub struct CrateInfo {
    pub name: String,
    pub version: String,
    pub manifest_path: PathBuf,
    pub root: PathBuf,
    pub source_files: Vec<PathBuf>,
    pub entry_points: Vec<EntryPoint>,
}

/// A single entry point recognized by judge's entry-point model (see todo.md §3.A).
#[derive(Debug)]
pub struct EntryPoint {
    pub kind: EntryPointKind,
    pub name: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryPointKind {
    Bin,
    Lib,
    Example,
    Test,
    Bench,
    BuildScript,
}

impl EntryPointKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Bin => "bin",
            Self::Lib => "lib",
            Self::Example => "example",
            Self::Test => "test",
            Self::Bench => "bench",
            Self::BuildScript => "build-script",
        }
    }

    fn from_cargo_kind(kind: &TargetKind) -> Option<Self> {
        match kind {
            TargetKind::Bin => Some(Self::Bin),
            TargetKind::Lib
            | TargetKind::RLib
            | TargetKind::DyLib
            | TargetKind::CDyLib
            | TargetKind::StaticLib
            | TargetKind::ProcMacro => Some(Self::Lib),
            TargetKind::Example => Some(Self::Example),
            TargetKind::Test => Some(Self::Test),
            TargetKind::Bench => Some(Self::Bench),
            TargetKind::CustomBuild => Some(Self::BuildScript),
            _ => None,
        }
    }
}

/// A discovered workspace: all local crates.
#[derive(Debug)]
pub struct Workspace {
    pub root: PathBuf,
    pub crates: Vec<CrateInfo>,
}

#[derive(Debug)]
pub enum IngestError {
    Metadata(cargo_metadata::Error),
    Io(std::io::Error),
}

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Metadata(err) => write!(f, "failed to read cargo metadata: {err}"),
            Self::Io(err) => write!(f, "failed to walk source files: {err}"),
        }
    }
}

impl std::error::Error for IngestError {}

impl From<cargo_metadata::Error> for IngestError {
    fn from(err: cargo_metadata::Error) -> Self {
        Self::Metadata(err)
    }
}

impl From<std::io::Error> for IngestError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Loads the workspace rooted at `manifest_path` (or the current directory's
/// `Cargo.toml` if `None`) by shelling out to `cargo metadata`.
pub fn load(manifest_path: Option<&Path>) -> Result<Workspace, IngestError> {
    let mut cmd = MetadataCommand::new();
    if let Some(path) = manifest_path {
        cmd.manifest_path(path);
    }
    let metadata = cmd.no_deps().exec()?;

    let mut crates = Vec::new();
    for package in &metadata.packages {
        let manifest_path: PathBuf = package.manifest_path.clone().into();
        let root = manifest_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let source_files = collect_source_files(&root)?;
        let entry_points = package
            .targets
            .iter()
            .flat_map(|target| {
                target.kind.iter().filter_map(move |kind| {
                    EntryPointKind::from_cargo_kind(kind).map(|kind| EntryPoint {
                        kind,
                        name: target.name.clone(),
                        path: target.src_path.clone().into(),
                    })
                })
            })
            .collect();

        crates.push(CrateInfo {
            name: package.name.to_string(),
            version: package.version.to_string(),
            manifest_path,
            root,
            source_files,
            entry_points,
        });
    }
    crates.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(Workspace {
        root: metadata.workspace_root.into(),
        crates,
    })
}

/// Recursively collects `.rs` files under `root`, skipping `target/` directories.
fn collect_source_files(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    #[test]
    fn load_discovers_crate_source_files_and_entry_points() {
        let dir = TempDir::new("ingest-basic");
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "fixture"
version = "0.1.0"
edition = "2021"
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src/bin")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn hello() {}\n").unwrap();
        std::fs::write(dir.join("src/bin/tool.rs"), "fn main() {}\n").unwrap();

        let manifest = dir.join("Cargo.toml");
        let workspace = load(Some(&manifest)).unwrap();

        assert_eq!(workspace.crates.len(), 1);
        let krate = &workspace.crates[0];
        assert_eq!(krate.name, "fixture");

        let mut files: Vec<_> = krate
            .source_files
            .iter()
            .map(|path| path.strip_prefix(&krate.root).unwrap().to_path_buf())
            .collect();
        files.sort();
        assert_eq!(
            files,
            vec![
                PathBuf::from("src/bin/tool.rs"),
                PathBuf::from("src/lib.rs")
            ]
        );

        let kinds: Vec<_> = krate.entry_points.iter().map(|entry| entry.kind).collect();
        assert!(kinds.contains(&EntryPointKind::Lib));
        assert!(kinds.contains(&EntryPointKind::Bin));
    }

    #[test]
    fn load_reports_metadata_error_for_a_missing_manifest() {
        let dir = TempDir::new("ingest-missing-manifest");
        let manifest = dir.join("Cargo.toml");

        let err = load(Some(&manifest)).unwrap_err();
        assert!(matches!(err, IngestError::Metadata(_)));
    }

    #[test]
    fn collect_source_files_skips_the_target_directory() {
        let dir = TempDir::new("ingest-skip-target");
        std::fs::create_dir_all(dir.join("target/debug")).unwrap();
        std::fs::write(dir.join("target/debug/generated.rs"), "// generated\n").unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn hello() {}\n").unwrap();

        let files = collect_source_files(&dir).unwrap();

        assert_eq!(files, vec![dir.join("src/lib.rs")]);
    }
}
