//! Ownership / code distribution via `git blame` (see todo.md §3.E
//! "Ownership / Code-Verteilung"). Deliberately scoped to three of the five
//! metrics in that table:
//!
//! - `primary-author-share`: the dominant author's share of a file's lines.
//! - `bus-factor`: the fewest top authors (by lines) whose cumulative share
//!   exceeds 50%.
//! - a stand-in for `knowledge-loss-risk`, scoped down to whether a file's
//!   *sole* author (bus-factor 1) is still active anywhere in the repo at
//!   all — not the full "line-share of authors with no commit in N months"
//!   from the table.
//!
//! `ownership-fragmentation` and `orphaned-code` are **not** implemented
//! here: both need thresholds or evidence (fan-in, test coverage) that
//! aren't defined or available yet, and inventing one would be policy, not
//! analysis.

use std::collections::HashSet;
use std::path::PathBuf;

use gix::bstr::{BStr, ByteSlice};

use crate::finding::{EvidenceClass, Finding, Location, Origin, Severity};
use crate::git::GitError;
use crate::ingest::Workspace;

/// Rule id used for [`FileOwnership`] findings whose bus factor is 1 (see
/// todo.md §3.E, §4's "3 Autoren, Bus-Faktor 1, Hauptautor seit 4 Monaten
/// inaktiv" example).
pub const LOW_BUS_FACTOR_RULE: &str = "low-bus-factor";
/// Bump when the low-bus-factor rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const LOW_BUS_FACTOR_RULE_REVISION: u32 = 1;

/// One author's share of a file's blamed lines.
#[derive(Debug, Clone)]
pub struct AuthorShare {
    pub email: String,
    pub lines: u32,
}

/// A single file's ownership distribution, derived from `git blame`.
#[derive(Debug, Clone)]
pub struct FileOwnership {
    pub file: PathBuf,
    /// Sorted descending by `lines`.
    pub authors: Vec<AuthorShare>,
    pub total_lines: u32,
    pub primary_author_share: f64,
    pub bus_factor: usize,
}

impl FileOwnership {
    /// Renders a `low-bus-factor` [`Finding`] if this file's bus factor is 1
    /// (a file with no blamed lines has a bus factor of 0 and yields no
    /// finding here — there's no author to attribute knowledge loss to).
    /// `Severity::Fail` if the sole author is no longer active anywhere in
    /// the repo (see todo.md §4's Decision Surface example); `Severity::Warn`
    /// if they still are. The evidence class is `heuristic`: the blame
    /// counts are exact historical facts, but "bus factor 1 = knowledge
    /// risk" is an interpretation of them — blame measures line authorship,
    /// not knowledge (todo.md §17.3).
    pub fn to_finding(&self, active_authors: &HashSet<String>) -> Option<Finding> {
        if self.bus_factor != 1 {
            return None;
        }
        let primary = self.authors.first()?;
        let severity = if active_authors.contains(&primary.email) {
            Severity::Warn
        } else {
            Severity::Fail
        };
        Some(Finding {
            id: format!("{LOW_BUS_FACTOR_RULE}:{}", self.file.display()),
            rule: LOW_BUS_FACTOR_RULE.to_string(),
            severity,
            location: Location {
                file: self.file.clone(),
                line: 1,
                item_path: primary.email.clone(),
            },
            evidence_class: EvidenceClass::Heuristic,
            origin: Origin::Code,
            evidence: None,
            caused_by: Vec::new(),
            causes: Vec::new(),
        })
    }
}

/// A per-file failure to blame, kept separate from a top-level repo-open
/// failure so one unblamable file doesn't abort the whole run.
#[derive(Debug)]
pub enum OwnershipError {
    Blame(PathBuf, String),
}

impl std::fmt::Display for OwnershipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blame(path, msg) => write!(f, "{}: failed to blame file: {msg}", path.display()),
        }
    }
}

impl std::error::Error for OwnershipError {}

/// Aggregated ownership results across a workspace.
#[derive(Debug, Default)]
pub struct WorkspaceOwnership {
    /// Every analyzed file's raw ownership data, not just the ones with
    /// findings.
    pub files: Vec<FileOwnership>,
    /// Only the `low-bus-factor` findings.
    pub findings: Vec<Finding>,
    pub errors: Vec<OwnershipError>,
}

/// Computes per-file ownership across every source file in `workspace` by
/// blaming each at `HEAD`, and emits `low-bus-factor` findings for files with
/// a bus factor of 1. A repository with no commits yet (unborn `HEAD`)
/// yields an empty result rather than an error, matching [`crate::git::hotspots`]'s
/// tolerance for "no git history at all". A failure to blame a single file
/// (e.g. it isn't tracked) is recorded in `errors` and that file is skipped,
/// not treated as a fatal error for the whole run.
pub fn analyze_workspace(
    workspace: &Workspace,
    window_days: i64,
) -> Result<WorkspaceOwnership, GitError> {
    let repo = gix::open(&workspace.root)?;

    let Ok(head_id) = repo.head_id() else {
        return Ok(WorkspaceOwnership::default());
    };

    let active_authors = crate::git::active_authors_since(&workspace.root, window_days)?;

    let mut result = WorkspaceOwnership::default();

    for krate in &workspace.crates {
        for source_file in &krate.source_files {
            let Ok(relative) = source_file.path.strip_prefix(&workspace.root) else {
                continue;
            };
            let relative_str = relative.to_string_lossy();
            let file_path: &BStr = BStr::new(relative_str.as_bytes());

            let outcome = repo.blame_file(
                file_path,
                head_id.detach(),
                gix::repository::blame_file::Options::default(),
            );
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(err) => {
                    result.errors.push(OwnershipError::Blame(
                        source_file.path.clone(),
                        err.to_string(),
                    ));
                    continue;
                }
            };

            match file_ownership(source_file.path.clone(), &repo, &outcome) {
                Ok(ownership) => {
                    if let Some(finding) = ownership.to_finding(&active_authors) {
                        result.findings.push(finding);
                    }
                    result.files.push(ownership);
                }
                Err(err) => result.errors.push(err),
            }
        }
    }

    Ok(result)
}

/// Sums blamed lines per author email from a blame `outcome`, then derives
/// the bus factor: the fewest top authors (by lines descending) whose
/// cumulative share exceeds 50% of the file's total blamed lines.
fn file_ownership(
    file: PathBuf,
    repo: &gix::Repository,
    outcome: &gix::blame::Outcome,
) -> Result<FileOwnership, OwnershipError> {
    let mut lines_by_email: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
    for entry in &outcome.entries {
        let commit = repo
            .find_commit(entry.commit_id)
            .map_err(|err| OwnershipError::Blame(file.clone(), err.to_string()))?;
        let author = commit
            .author()
            .map_err(|err| OwnershipError::Blame(file.clone(), err.to_string()))?;
        let email = author.email.to_str_lossy().trim().to_string();
        *lines_by_email.entry(email).or_insert(0) += entry.len.get();
    }

    let mut authors: Vec<AuthorShare> = lines_by_email
        .into_iter()
        .map(|(email, lines)| AuthorShare { email, lines })
        .collect();
    authors.sort_by(|a, b| b.lines.cmp(&a.lines).then_with(|| a.email.cmp(&b.email)));

    let total_lines: u32 = authors.iter().map(|author| author.lines).sum();
    let primary_author_share = if total_lines == 0 {
        0.0
    } else {
        authors[0].lines as f64 / total_lines as f64
    };

    let mut cumulative = 0u32;
    let mut bus_factor = 0usize;
    for author in &authors {
        cumulative += author.lines;
        bus_factor += 1;
        if f64::from(cumulative) > f64::from(total_lines) * 0.5 {
            break;
        }
    }

    Ok(FileOwnership {
        file,
        authors,
        total_lines,
        primary_author_share,
        bus_factor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::{CrateInfo, SourceFile, SourceKind};
    use crate::test_util::TempDir;

    fn git(dir: &std::path::Path, args: &[&str]) {
        run_git(dir, args, &[]);
    }

    fn run_git(dir: &std::path::Path, args: &[&str], extra_env: &[(&str, &str)]) {
        let status = std::process::Command::new("git")
            .args([
                "-c",
                "user.name=judge-test",
                "-c",
                "user.email=test@example.com",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(dir)
            .envs(extra_env.iter().copied())
            .status()
            .expect("failed to run git — required for these fixtures");
        assert!(status.success(), "git {args:?} failed");
    }

    fn run_git_as(dir: &std::path::Path, email: &str, args: &[&str], extra_env: &[(&str, &str)]) {
        let status = std::process::Command::new("git")
            .args([
                "-c",
                &format!("user.name={email}"),
                "-c",
                &format!("user.email={email}"),
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(dir)
            .envs(extra_env.iter().copied())
            .status()
            .expect("failed to run git — required for these fixtures");
        assert!(status.success(), "git {args:?} failed");
    }

    fn workspace_of(root: PathBuf, file: PathBuf) -> Workspace {
        Workspace {
            root: root.clone(),
            crates: vec![CrateInfo {
                name: "fixture".to_string(),
                version: "0.1.0".to_string(),
                manifest_path: root.join("Cargo.toml"),
                root,
                source_files: vec![SourceFile {
                    path: file,
                    kind: SourceKind::Authored,
                }],
                entry_points: Vec::new(),
                dependencies: Vec::new(),
            }],
        }
    }

    #[test]
    fn single_author_file_has_bus_factor_one_and_full_share() {
        let dir = TempDir::new("ownership-single-author");
        git(&dir, &["init", "-q", "-b", "main"]);

        let file = dir.join("solo.rs");
        std::fs::write(&file, "fn a() {}\nfn b() {}\nfn c() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);

        let workspace = workspace_of(dir.to_path_buf(), file.clone());
        let report = analyze_workspace(&workspace, crate::git::DEFAULT_WINDOW_DAYS).unwrap();

        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(report.files.len(), 1);
        let ownership = &report.files[0];
        assert_eq!(ownership.bus_factor, 1);
        assert_eq!(ownership.primary_author_share, 1.0);
    }

    #[test]
    fn two_roughly_equal_authors_have_bus_factor_two() {
        let dir = TempDir::new("ownership-two-authors");
        git(&dir, &["init", "-q", "-b", "main"]);

        let file = dir.join("shared.rs");
        std::fs::write(&file, "fn a() {}\nfn b() {}\n").unwrap();
        run_git_as(&dir, "one@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "one@example.com",
            &["commit", "-q", "-m", "first half"],
            &[],
        );

        std::fs::write(&file, "fn a() {}\nfn b() {}\nfn c() {}\nfn d() {}\n").unwrap();
        run_git_as(&dir, "two@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "two@example.com",
            &["commit", "-q", "-m", "second half"],
            &[],
        );

        let workspace = workspace_of(dir.to_path_buf(), file.clone());
        let report = analyze_workspace(&workspace, crate::git::DEFAULT_WINDOW_DAYS).unwrap();

        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(report.files.len(), 1);
        let ownership = &report.files[0];
        assert_eq!(ownership.authors.len(), 2);
        assert_eq!(ownership.bus_factor, 2);
    }

    #[test]
    fn low_bus_factor_finding_is_warn_when_the_sole_author_is_still_active() {
        let dir = TempDir::new("ownership-active-author");
        git(&dir, &["init", "-q", "-b", "main"]);

        let file = dir.join("solo.rs");
        std::fs::write(&file, "fn a() {}\n").unwrap();
        run_git_as(&dir, "solo@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "solo@example.com",
            &["commit", "-q", "-m", "initial"],
            &[],
        );

        let workspace = workspace_of(dir.to_path_buf(), file.clone());
        let report = analyze_workspace(&workspace, crate::git::DEFAULT_WINDOW_DAYS).unwrap();

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule, LOW_BUS_FACTOR_RULE);
        assert_eq!(report.findings[0].severity, Severity::Warn);
        assert_eq!(report.findings[0].location.item_path, "solo@example.com");
    }

    #[test]
    fn low_bus_factor_finding_is_fail_when_the_sole_author_is_inactive() {
        let dir = TempDir::new("ownership-inactive-author");
        git(&dir, &["init", "-q", "-b", "main"]);

        let old_date = [
            ("GIT_AUTHOR_DATE", "2000-01-01T00:00:00"),
            ("GIT_COMMITTER_DATE", "2000-01-01T00:00:00"),
        ];
        let file = dir.join("solo.rs");
        std::fs::write(&file, "fn a() {}\n").unwrap();
        run_git_as(&dir, "gone@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "gone@example.com",
            &["commit", "-q", "-m", "initial"],
            &old_date,
        );

        let workspace = workspace_of(dir.to_path_buf(), file.clone());
        let report = analyze_workspace(&workspace, 30).unwrap();

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, Severity::Fail);
        assert_eq!(report.findings[0].location.item_path, "gone@example.com");
    }

    #[test]
    fn repo_without_commits_yields_empty_result_not_an_error() {
        let dir = TempDir::new("ownership-no-commits");
        git(&dir, &["init", "-q", "-b", "main"]);

        let workspace = Workspace {
            root: dir.to_path_buf(),
            crates: Vec::new(),
        };
        let report = analyze_workspace(&workspace, crate::git::DEFAULT_WINDOW_DAYS).unwrap();

        assert!(report.files.is_empty());
        assert!(report.findings.is_empty());
        assert!(report.errors.is_empty());
    }
}
