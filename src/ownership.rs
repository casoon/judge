//! Ownership / code distribution via `git blame` (see todo.md §3.E
//! "Ownership / Code-Verteilung"). Deliberately scoped to four of the five
//! metrics in that table:
//!
//! - `primary-author-share`: the dominant author's share of a file's lines.
//! - `bus-factor`: the fewest top authors (by lines) whose cumulative share
//!   exceeds 50%.
//! - `knowledge-loss-risk`: the full "line-share of authors with no commit
//!   in N months" from the table — see
//!   [`FileOwnership::to_knowledge_loss_risk_finding`]. `low-bus-factor` is
//!   the narrower single-dominant-author special case of the same
//!   underlying signal; the two are expected to co-fire often (a
//!   bus-factor-1 file with an inactive sole author trivially has an
//!   inactive share near 100%), and that overlap is intentional, not a bug
//!   — see that method's docs for the diffused-ownership case
//!   `knowledge-loss-risk` newly covers.
//! - `ownership-fragmentation`: many small blame shares with no dominant
//!   owner (advisory heuristic — see
//!   [`FileOwnership::to_fragmentation_finding`]).
//!
//! `orphaned-code` is **not** implemented here: it needs evidence (fan-in,
//! test-path coverage) from the Deep Tier that isn't available in this pass.
//! It lives in [`crate::slop_structural_deep`] instead, which already loads
//! the Deep Tier context and fan-in data a sibling rule
//! (`connectivity-drop`) needs anyway — `orphaned-code` only adds this
//! module's [`FileOwnership`]/`active_authors_since` data on top, via
//! `dominant_author_by_file`/`active_authors` parameters threaded in from
//! the CLI.

use std::collections::HashSet;
use std::path::PathBuf;

use gix::bstr::{BStr, ByteSlice};

use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::git::GitError;
use crate::ingest::Workspace;

/// Rule id used for [`FileOwnership`] findings whose bus factor is 1 (see
/// todo.md §3.E, §4's "3 Autoren, Bus-Faktor 1, Hauptautor seit 4 Monaten
/// inaktiv" example).
pub const LOW_BUS_FACTOR_RULE: &str = "low-bus-factor";
/// Bump when the low-bus-factor rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const LOW_BUS_FACTOR_RULE_REVISION: u32 = 2;

/// `low-bus-factor` only fires if the repository has at least this many
/// distinct authors active within the window also used for the per-file
/// active/inactive check (see [`analyze_workspace`]'s use of
/// `active_authors_since`). With a single repo-wide author, every file is
/// bus-factor 1 by construction — there is no "knowledge concentration" to
/// compare against, so the metric is categorially inapplicable, not merely
/// statistically weak (see GitHub issue #2: 586 commits, 1 author, 333
/// `low-bus-factor` findings — practically every file). Two is the minimum
/// author count at which the comparison becomes meaningful at all.
///
/// `pub(crate)`: also reused by [`crate::slop_structural_deep`]'s
/// `orphaned-code` for the same repo-level gate on its own
/// dominant-author-inactive leg.
pub(crate) const LOW_BUS_FACTOR_MIN_REPO_AUTHORS: usize = 2;

/// Rule id used for [`FileOwnership`] findings whose share of blamed lines
/// from now-inactive authors exceeds [`KNOWLEDGE_LOSS_RISK_SHARE_THRESHOLD`]
/// (see todo.md §3.E "knowledge-loss-risk": "line-share of authors with no
/// commit in N months").
pub const KNOWLEDGE_LOSS_RISK_RULE: &str = "knowledge-loss-risk";
/// Bump when the knowledge-loss-risk rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const KNOWLEDGE_LOSS_RISK_RULE_REVISION: u32 = 1;

/// `knowledge-loss-risk` fires once the share of a file's blamed lines
/// belonging to authors no longer active anywhere in the repo exceeds this
/// fraction — a majority of the file's current lines, the same 50% framing
/// `low-bus-factor` already uses for its own bus-factor cutoff.
const KNOWLEDGE_LOSS_RISK_SHARE_THRESHOLD: f64 = 0.5;

/// Rule id for files whose blame is split into many small author shares with
/// no dominant owner (todo.md §3.E: "Verteilung vieler kleiner Blame-Anteile;
/// 'diffuse Verantwortung' nur als Interpretation").
pub const OWNERSHIP_FRAGMENTATION_RULE: &str = "ownership-fragmentation";
/// Bump when the ownership-fragmentation rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const OWNERSHIP_FRAGMENTATION_RULE_REVISION: u32 = 1;

/// Interpretation-limiting caption for `ownership-fragmentation` output
/// (todo.md §16.7, §17): the blame shares are facts; the reading is not.
pub const OWNERSHIP_FRAGMENTATION_NOTE: &str = "many small blame shares — diffuse responsibility is one possible reading, not a proven problem";

/// A file counts as fragmented only with at least this many blamed authors.
/// Three authors on one file is ordinary collaboration; the todo.md §3.E
/// signal is "many small shares".
const FRAGMENTATION_MIN_AUTHORS: usize = 4;
/// ...and only if the largest single author share stays below this — a file
/// with a dominant owner isn't fragmented no matter how many minor
/// contributors it has.
const FRAGMENTATION_MAX_TOP_SHARE: f64 = 0.35;
/// Files with fewer blamed lines than this are skipped: share percentages
/// over a handful of lines say nothing about responsibility.
const FRAGMENTATION_MIN_LINES: u32 = 50;
/// The evidence JSON lists at most this many top author shares.
const FRAGMENTATION_EVIDENCE_SHARES: usize = 5;

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
    /// not knowledge (todo.md §17.3). Callers must additionally gate this on
    /// [`LOW_BUS_FACTOR_MIN_REPO_AUTHORS`] at the repo level (see
    /// [`analyze_workspace`]) — this method has no visibility into how many
    /// authors the repository has overall.
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
            id: format!("{LOW_BUS_FACTOR_RULE}:{}", self.file.display()).into(),
            rule: LOW_BUS_FACTOR_RULE.into(),
            severity,
            location: Location {
                file: self.file.clone(),
                line: OneBasedLine::FIRST,
                item_path: primary.email.clone(),
            },
            evidence_class: EvidenceClass::Heuristic,
            origin: Origin::Code,
            evidence: None,
            caused_by: Vec::new(),
            causes: Vec::new(),
        })
    }

    /// Renders a `knowledge-loss-risk` [`Finding`] if the share of this
    /// file's blamed lines belonging to authors no longer active anywhere in
    /// the repo exceeds [`KNOWLEDGE_LOSS_RISK_SHARE_THRESHOLD`]. This
    /// generalizes `low-bus-factor` beyond the single-dominant-author case:
    /// a file can have several roughly-equal-share authors — no individual
    /// author dominant enough for `bus_factor` to be 1 — where all of them
    /// have since gone inactive, diffusing the risk `low-bus-factor` alone
    /// would miss (it only ever looks at bus-factor-1 files). A bus-factor-1
    /// file with an inactive sole author trivially has an inactive share
    /// near 100% here too, so the two rules are expected to co-fire often —
    /// that overlap is intentional (see the module doc comment), not
    /// double-counting. `Severity::Fail` if none of the file's blamed
    /// authors are currently active (the strongest form of the signal);
    /// `Severity::Warn` if some are, but their combined share still doesn't
    /// reach a majority. The evidence class is `heuristic` for the same
    /// reason as `low-bus-factor`: the blame shares are exact historical
    /// facts, but "this is a knowledge risk" is an interpretation of them.
    /// Callers must additionally gate this on
    /// [`LOW_BUS_FACTOR_MIN_REPO_AUTHORS`] at the repo level (see
    /// [`analyze_workspace`]), same as `low-bus-factor` — this method has no
    /// visibility into how many authors the repository has overall.
    pub fn to_knowledge_loss_risk_finding(
        &self,
        active_authors: &HashSet<String>,
    ) -> Option<Finding> {
        if self.total_lines == 0 {
            return None;
        }
        let mut inactive_lines: u32 = 0;
        let mut inactive_authors: Vec<String> = Vec::new();
        let mut active_authors_count = 0usize;
        for author in &self.authors {
            if active_authors.contains(&author.email) {
                active_authors_count += 1;
            } else {
                inactive_lines += author.lines;
                inactive_authors.push(author.email.clone());
            }
        }
        let inactive_share = f64::from(inactive_lines) / f64::from(self.total_lines);
        if inactive_share <= KNOWLEDGE_LOSS_RISK_SHARE_THRESHOLD {
            return None;
        }
        inactive_authors.sort();

        let severity = if active_authors_count == 0 {
            Severity::Fail
        } else {
            Severity::Warn
        };
        Some(Finding {
            id: format!("{KNOWLEDGE_LOSS_RISK_RULE}:{}", self.file.display()).into(),
            rule: KNOWLEDGE_LOSS_RISK_RULE.into(),
            severity,
            location: Location {
                file: self.file.clone(),
                line: OneBasedLine::FIRST,
                item_path: format!(
                    "{:.0}% of lines from inactive authors",
                    inactive_share * 100.0
                ),
            },
            evidence_class: EvidenceClass::Heuristic,
            origin: Origin::Code,
            evidence: Some(serde_json::json!({
                "file": self.file.display().to_string(),
                "inactive_share": inactive_share,
                "total_lines": self.total_lines,
                "inactive_authors": inactive_authors,
                "active_authors_count": active_authors_count,
            })),
            caused_by: Vec::new(),
            causes: Vec::new(),
        })
    }

    /// Renders an `ownership-fragmentation` [`Finding`] if this file's blame
    /// is split across at least [`FRAGMENTATION_MIN_AUTHORS`] authors, none
    /// of whom holds [`FRAGMENTATION_MAX_TOP_SHARE`] or more of the lines,
    /// and the file has at least [`FRAGMENTATION_MIN_LINES`] blamed lines.
    /// Always `Severity::Info` and `EvidenceClass::Heuristic` (advisory,
    /// never gating — [`crate::finding::EvidenceClass::is_gating`]): the
    /// shares are exact blame facts, but "many small shares = diffuse
    /// responsibility" is one possible reading of them, not proof (todo.md
    /// §16.7, §17). Author emails appear in the evidence, matching how
    /// `low-bus-factor` names its primary author; `shares` is capped at the
    /// top [`FRAGMENTATION_EVIDENCE_SHARES`].
    pub fn to_fragmentation_finding(&self) -> Option<Finding> {
        if self.total_lines < FRAGMENTATION_MIN_LINES
            || self.authors.len() < FRAGMENTATION_MIN_AUTHORS
            || self.primary_author_share >= FRAGMENTATION_MAX_TOP_SHARE
        {
            return None;
        }
        let shares: Vec<serde_json::Value> = self
            .authors
            .iter()
            .take(FRAGMENTATION_EVIDENCE_SHARES)
            .map(|author| serde_json::json!({ "author": author.email, "lines": author.lines }))
            .collect();
        Some(Finding {
            id: format!("{OWNERSHIP_FRAGMENTATION_RULE}:{}", self.file.display()).into(),
            rule: OWNERSHIP_FRAGMENTATION_RULE.into(),
            severity: Severity::Info,
            location: Location {
                file: self.file.clone(),
                line: OneBasedLine::FIRST,
                item_path: format!(
                    "{} authors, top share {:.0}%",
                    self.authors.len(),
                    self.primary_author_share * 100.0
                ),
            },
            evidence_class: EvidenceClass::Heuristic,
            origin: Origin::Code,
            evidence: Some(serde_json::json!({
                "authors": self.authors.len(),
                "top_share": self.primary_author_share,
                "total_lines": self.total_lines,
                "shares": shares,
            })),
            caused_by: Vec::new(),
            causes: Vec::new(),
        })
    }
}

/// A per-file failure to blame, kept separate from a top-level repo-open
/// failure so one unblamable file doesn't abort the whole run.
#[derive(Debug)]
pub enum OwnershipError {
    Blame(PathBuf, Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for OwnershipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blame(path, err) => write!(f, "{}: failed to blame file: {err}", path.display()),
        }
    }
}

impl std::error::Error for OwnershipError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Blame(_, err) => Some(err.as_ref()),
        }
    }
}

/// Aggregated ownership results across a workspace.
#[derive(Debug, Default)]
pub struct WorkspaceOwnership {
    /// Every analyzed file's raw ownership data, not just the ones with
    /// findings.
    pub files: Vec<FileOwnership>,
    /// The `low-bus-factor`, `knowledge-loss-risk`, and
    /// `ownership-fragmentation` findings.
    pub findings: Vec<Finding>,
    pub errors: Vec<OwnershipError>,
}

/// Computes per-file ownership across every source file in `workspace` by
/// blaming each at `HEAD`, and emits `low-bus-factor` findings for files with
/// a bus factor of 1, `knowledge-loss-risk` findings for files where a
/// majority of blamed lines belong to now-inactive authors, plus
/// `ownership-fragmentation` findings for files with many small blame
/// shares. `low-bus-factor` and `knowledge-loss-risk` are both skipped for
/// the whole workspace if the repository has fewer than
/// [`LOW_BUS_FACTOR_MIN_REPO_AUTHORS`] distinct authors active in
/// `window_days` (see that constant's docs and GitHub issue #2) — the
/// repo-wide author count is computed once via `active_authors_since`, not
/// per file. A repository with no commits yet (unborn `HEAD`) yields an
/// empty result rather than an error, matching [`crate::git::hotspots`]'s
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
    let repo_has_enough_authors_for_bus_factor =
        active_authors.len() >= LOW_BUS_FACTOR_MIN_REPO_AUTHORS;

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
                gix::repository::blame_file::Options {
                    // Without this, gix does not follow a `git mv` rename at
                    // all (see `gix_blame`'s `tree_diff_without_rewrites_at_file_path`):
                    // a pure rename with no content change is treated as an
                    // `Addition`, so blame stops at the rename commit and
                    // misattributes every pre-rename line to whoever ran
                    // `git mv`, instead of the line's actual author. Plain
                    // `git blame` follows renames of the blamed file by
                    // default (no `--follow` needed — that flag is for `git
                    // log`), so this matches that default rather than
                    // introducing new behavior.
                    rewrites: Some(gix::diff::Rewrites::default()),
                    ..Default::default()
                },
            );
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(err) => {
                    result
                        .errors
                        .push(OwnershipError::Blame(source_file.path.clone(), err.into()));
                    continue;
                }
            };

            match file_ownership(source_file.path.clone(), &repo, &outcome) {
                Ok(ownership) => {
                    if repo_has_enough_authors_for_bus_factor
                        && let Some(finding) = ownership.to_finding(&active_authors)
                    {
                        result.findings.push(finding);
                    }
                    if repo_has_enough_authors_for_bus_factor
                        && let Some(finding) =
                            ownership.to_knowledge_loss_risk_finding(&active_authors)
                    {
                        result.findings.push(finding);
                    }
                    if let Some(finding) = ownership.to_fragmentation_finding() {
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
            .map_err(|err| OwnershipError::Blame(file.clone(), err.into()))?;
        let author = commit
            .author()
            .map_err(|err| OwnershipError::Blame(file.clone(), err.into()))?;
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
        workspace_of_files(root, vec![file])
    }

    fn workspace_of_files(root: PathBuf, files: Vec<PathBuf>) -> Workspace {
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

        // A second, unrelated file/author so the repo has the
        // LOW_BUS_FACTOR_MIN_REPO_AUTHORS distinct authors the low-bus-factor
        // guard requires; the analyzed file's ownership is unaffected.
        let other_file = dir.join("other.rs");
        std::fs::write(&other_file, "fn z() {}\n").unwrap();
        run_git_as(&dir, "other@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "other@example.com",
            &["commit", "-q", "-m", "unrelated"],
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

        // Two recent, unrelated authors so the repo has the
        // LOW_BUS_FACTOR_MIN_REPO_AUTHORS distinct authors the low-bus-factor
        // guard requires within the 30-day window, without either of them
        // being the analyzed file's (inactive) author.
        let other_file = dir.join("other.rs");
        std::fs::write(&other_file, "fn y() {}\n").unwrap();
        run_git_as(&dir, "recent-a@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "recent-a@example.com",
            &["commit", "-q", "-m", "unrelated a"],
            &[],
        );
        std::fs::write(&other_file, "fn y() {}\nfn z() {}\n").unwrap();
        run_git_as(&dir, "recent-b@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "recent-b@example.com",
            &["commit", "-q", "-m", "unrelated b"],
            &[],
        );

        let workspace = workspace_of(dir.to_path_buf(), file.clone());
        let report = analyze_workspace(&workspace, 30).unwrap();

        // A bus-factor-1 file with an inactive sole author trivially has an
        // inactive share near 100%, so it's expected to ALSO fire
        // `knowledge-loss-risk` — see that method's docs on the intentional
        // overlap between the two rules.
        assert_eq!(report.findings.len(), 2, "{:?}", report.findings);
        assert_eq!(report.findings[0].rule, LOW_BUS_FACTOR_RULE);
        assert_eq!(report.findings[0].severity, Severity::Fail);
        assert_eq!(report.findings[0].location.item_path, "gone@example.com");

        assert_eq!(report.findings[1].rule, KNOWLEDGE_LOSS_RISK_RULE);
        assert_eq!(report.findings[1].severity, Severity::Fail);
        let evidence = report.findings[1]
            .evidence
            .as_ref()
            .expect("evidence must be set");
        assert_eq!(evidence["inactive_share"], 1.0);
        assert_eq!(evidence["active_authors_count"], 0);
        assert_eq!(
            evidence["inactive_authors"],
            serde_json::json!(["gone@example.com"])
        );
    }

    /// Regression test for GitHub issue #2: on a repo with a single overall
    /// author, every file is bus-factor 1 by construction (there's no
    /// "concentration" to compare against), so `low-bus-factor` must not
    /// fire at all — even though each file's own bus factor is still 1.
    #[test]
    fn solo_author_repo_yields_no_low_bus_factor_findings_despite_bus_factor_one_everywhere() {
        let dir = TempDir::new("ownership-solo-repo");
        git(&dir, &["init", "-q", "-b", "main"]);

        let small = dir.join("small.rs");
        std::fs::write(&small, "fn a() {}\n").unwrap();
        let large = dir.join("large.rs");
        std::fs::write(
            &large,
            "fn a() {}\nfn b() {}\nfn c() {}\nfn d() {}\nfn e() {}\n",
        )
        .unwrap();
        run_git_as(&dir, "solo@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "solo@example.com",
            &["commit", "-q", "-m", "initial"],
            &[],
        );

        let workspace = workspace_of_files(dir.to_path_buf(), vec![small, large]);
        let report = analyze_workspace(&workspace, crate::git::DEFAULT_WINDOW_DAYS).unwrap();

        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(report.files.len(), 2);
        assert!(
            report.files.iter().all(|f| f.bus_factor == 1),
            "{:?}",
            report.files
        );
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.rule != LOW_BUS_FACTOR_RULE
                    && finding.rule != KNOWLEDGE_LOSS_RISK_RULE),
            "{:?}",
            report.findings
        );
    }

    /// Grows `file` by `lines_per_author` lines per author, committing each
    /// chunk as a different author so blame splits accordingly.
    fn commit_chunks_as(
        dir: &std::path::Path,
        file: &std::path::Path,
        authors: &[&str],
        lines_per_author: &[usize],
    ) {
        let mut contents = String::new();
        for (index, (email, lines)) in authors.iter().zip(lines_per_author).enumerate() {
            for line in 0..*lines {
                contents.push_str(&format!("fn f{index}_{line}() {{}}\n"));
            }
            std::fs::write(file, &contents).unwrap();
            run_git_as(dir, email, &["add", "."], &[]);
            run_git_as(dir, email, &["commit", "-q", "-m", "chunk"], &[]);
        }
    }

    /// Same as [`commit_chunks_as`], but each commit runs with `extra_env`
    /// set (e.g. `GIT_AUTHOR_DATE`/`GIT_COMMITTER_DATE`), so tests can
    /// backdate every chunk's author to make them inactive.
    fn commit_chunks_as_with_env(
        dir: &std::path::Path,
        file: &std::path::Path,
        authors: &[&str],
        lines_per_author: &[usize],
        extra_env: &[(&str, &str)],
    ) {
        let mut contents = String::new();
        for (index, (email, lines)) in authors.iter().zip(lines_per_author).enumerate() {
            for line in 0..*lines {
                contents.push_str(&format!("fn f{index}_{line}() {{}}\n"));
            }
            std::fs::write(file, &contents).unwrap();
            run_git_as(dir, email, &["add", "."], extra_env);
            run_git_as(dir, email, &["commit", "-q", "-m", "chunk"], extra_env);
        }
    }

    #[test]
    fn file_with_several_roughly_equal_now_inactive_authors_fires_knowledge_loss_risk() {
        let dir = TempDir::new("ownership-diffused-inactive");
        git(&dir, &["init", "-q", "-b", "main"]);

        let old_date = [
            ("GIT_AUTHOR_DATE", "2000-01-01T00:00:00"),
            ("GIT_COMMITTER_DATE", "2000-01-01T00:00:00"),
        ];
        let file = dir.join("shared.rs");
        commit_chunks_as_with_env(
            &dir,
            &file,
            &["a@example.com", "b@example.com", "c@example.com"],
            &[10, 10, 10],
            &old_date,
        );

        // Two recent, unrelated authors so the repo has the
        // LOW_BUS_FACTOR_MIN_REPO_AUTHORS distinct authors the gate
        // requires, without either of them being one of the analyzed file's
        // (all inactive) authors.
        let other_file = dir.join("other.rs");
        std::fs::write(&other_file, "fn y() {}\n").unwrap();
        run_git_as(&dir, "recent-a@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "recent-a@example.com",
            &["commit", "-q", "-m", "unrelated a"],
            &[],
        );
        std::fs::write(&other_file, "fn y() {}\nfn z() {}\n").unwrap();
        run_git_as(&dir, "recent-b@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "recent-b@example.com",
            &["commit", "-q", "-m", "unrelated b"],
            &[],
        );

        let workspace = workspace_of(dir.to_path_buf(), file.clone());
        let report = analyze_workspace(&workspace, 30).unwrap();

        assert!(report.errors.is_empty(), "{:?}", report.errors);
        // No individual author dominates (bus_factor > 1), so low-bus-factor
        // never looks at this file — the diffused-ownership case
        // knowledge-loss-risk newly covers.
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.rule != LOW_BUS_FACTOR_RULE),
            "{:?}",
            report.findings
        );
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.rule == KNOWLEDGE_LOSS_RISK_RULE)
            .expect("knowledge-loss-risk must fire");
        assert_eq!(finding.severity, Severity::Fail);
        let evidence = finding.evidence.as_ref().expect("evidence must be set");
        assert_eq!(evidence["inactive_share"], 1.0);
        assert_eq!(evidence["active_authors_count"], 0);
        assert_eq!(
            evidence["inactive_authors"],
            serde_json::json!(["a@example.com", "b@example.com", "c@example.com"])
        );
    }

    #[test]
    fn file_with_active_majority_and_one_inactive_minor_contributor_does_not_fire_knowledge_loss_risk()
     {
        let dir = TempDir::new("ownership-active-majority");
        git(&dir, &["init", "-q", "-b", "main"]);

        let old_date = [
            ("GIT_AUTHOR_DATE", "2000-01-01T00:00:00"),
            ("GIT_COMMITTER_DATE", "2000-01-01T00:00:00"),
        ];
        let file = dir.join("mostly-active.rs");
        // Minor, backdated/inactive contributor writes first.
        let mut contents = String::new();
        for line in 0..10 {
            contents.push_str(&format!("fn f0_{line}() {{}}\n"));
        }
        std::fs::write(&file, &contents).unwrap();
        run_git_as(&dir, "gone@example.com", &["add", "."], &old_date);
        run_git_as(
            &dir,
            "gone@example.com",
            &["commit", "-q", "-m", "minor, inactive"],
            &old_date,
        );

        // Majority-share, recent/active author adds much more on top.
        for line in 0..40 {
            contents.push_str(&format!("fn f1_{line}() {{}}\n"));
        }
        std::fs::write(&file, &contents).unwrap();
        run_git_as(&dir, "active@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "active@example.com",
            &["commit", "-q", "-m", "majority, active"],
            &[],
        );

        // A second, unrelated recent author so the repo has the
        // LOW_BUS_FACTOR_MIN_REPO_AUTHORS distinct authors the gate
        // requires.
        let other_file = dir.join("other.rs");
        std::fs::write(&other_file, "fn z() {}\n").unwrap();
        run_git_as(&dir, "other@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "other@example.com",
            &["commit", "-q", "-m", "unrelated"],
            &[],
        );

        let workspace = workspace_of(dir.to_path_buf(), file.clone());
        let report = analyze_workspace(&workspace, 30).unwrap();

        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.rule != KNOWLEDGE_LOSS_RISK_RULE),
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn fragmented_file_with_many_small_shares_yields_a_finding() {
        let dir = TempDir::new("ownership-fragmented");
        git(&dir, &["init", "-q", "-b", "main"]);

        let file = dir.join("frag.rs");
        commit_chunks_as(
            &dir,
            &file,
            &[
                "a@example.com",
                "b@example.com",
                "c@example.com",
                "d@example.com",
            ],
            &[15, 15, 15, 15],
        );

        let workspace = workspace_of(dir.to_path_buf(), file.clone());
        let report = analyze_workspace(&workspace, crate::git::DEFAULT_WINDOW_DAYS).unwrap();

        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
        let finding = &report.findings[0];
        assert_eq!(finding.rule, OWNERSHIP_FRAGMENTATION_RULE);
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.location.file, file);
        let evidence = finding.evidence.as_ref().expect("evidence must be set");
        assert_eq!(evidence["authors"], 4);
        assert_eq!(evidence["top_share"], 0.25);
        assert_eq!(evidence["total_lines"], 60);
        assert_eq!(evidence["shares"].as_array().unwrap().len(), 4);
        assert_eq!(evidence["shares"][0]["lines"], 15);
    }

    #[test]
    fn file_with_a_dominant_author_yields_no_fragmentation_finding() {
        let dir = TempDir::new("ownership-dominant-author");
        git(&dir, &["init", "-q", "-b", "main"]);

        let file = dir.join("owned.rs");
        commit_chunks_as(
            &dir,
            &file,
            &[
                "a@example.com",
                "b@example.com",
                "c@example.com",
                "d@example.com",
            ],
            &[30, 10, 10, 10],
        );

        let workspace = workspace_of(dir.to_path_buf(), file.clone());
        let report = analyze_workspace(&workspace, crate::git::DEFAULT_WINDOW_DAYS).unwrap();

        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert!(report.findings.is_empty(), "{:?}", report.findings);
    }

    #[test]
    fn small_file_below_the_line_threshold_yields_no_fragmentation_finding() {
        let dir = TempDir::new("ownership-small-file");
        git(&dir, &["init", "-q", "-b", "main"]);

        let file = dir.join("small.rs");
        commit_chunks_as(
            &dir,
            &file,
            &[
                "a@example.com",
                "b@example.com",
                "c@example.com",
                "d@example.com",
            ],
            &[3, 3, 3, 3],
        );

        let workspace = workspace_of(dir.to_path_buf(), file.clone());
        let report = analyze_workspace(&workspace, crate::git::DEFAULT_WINDOW_DAYS).unwrap();

        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert!(report.findings.is_empty(), "{:?}", report.findings);
    }

    #[test]
    fn fragmentation_finding_is_heuristic_and_never_gating() {
        let ownership = FileOwnership {
            file: PathBuf::from("src/frag.rs"),
            authors: ["a", "b", "c", "d"]
                .map(|name| AuthorShare {
                    email: format!("{name}@example.com"),
                    lines: 15,
                })
                .to_vec(),
            total_lines: 60,
            primary_author_share: 0.25,
            bus_factor: 3,
        };
        let finding = ownership
            .to_fragmentation_finding()
            .expect("all thresholds are met");
        assert_eq!(finding.evidence_class, EvidenceClass::Heuristic);
        assert!(
            !finding.is_gating(),
            "advisory heuristic must never affect a verdict"
        );
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

    /// Regression test for a bug found while probing `low-bus-factor`/
    /// `ownership-fragmentation` for undecidable fixtures (todo.md §17.5):
    /// `gix::repository::blame_file::Options::default()` leaves `rewrites:
    /// None`, so `gix_blame` never tries rename detection for the blamed
    /// file (see `gix_blame::file::function::tree_diff_at_file_path`, which
    /// only retries with rewrite detection — and only for the current
    /// commit's diff, not by walking further back — when `rewrites` is
    /// `Some`). A pure `git mv` with no content change was, before the fix
    /// in [`analyze_workspace`], treated as an `Addition` at the rename
    /// commit, so blame stopped there and misattributed every pre-rename
    /// line to whoever ran `git mv` instead of that line's actual author.
    /// Plain `git blame <file>` (verified against the real CLI, no flags)
    /// follows a rename of the blamed file by default — `--follow` is a
    /// `git log`-only flag, irrelevant to `git blame` — so this was a
    /// genuine divergence from git's own behavior, not just an
    /// interpretation question.
    #[test]
    fn blame_follows_a_pure_rename_and_credits_the_original_author() {
        let dir = TempDir::new("ownership-rename");
        git(&dir, &["init", "-q", "-b", "main"]);

        let old = dir.join("old.rs");
        std::fs::write(&old, "fn a() {}\nfn b() {}\nfn c() {}\n").unwrap();
        run_git_as(&dir, "a@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "a@example.com",
            &["commit", "-q", "-m", "author a initial"],
            &[],
        );

        // Renamed by a third author who never touches the content — a pure
        // `git mv`. If blame doesn't follow the rename, these three lines
        // get misattributed to this rename author instead of `a`.
        let new = dir.join("new.rs");
        run_git_as(&dir, "c@example.com", &["mv", "old.rs", "new.rs"], &[]);
        run_git_as(
            &dir,
            "c@example.com",
            &["commit", "-q", "-m", "rename"],
            &[],
        );

        std::fs::write(
            &new,
            "fn a() {}\nfn b() {}\nfn c() {}\nfn d() {}\nfn e() {}\n",
        )
        .unwrap();
        run_git_as(&dir, "b@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "b@example.com",
            &["commit", "-q", "-m", "author b adds"],
            &[],
        );

        let workspace = workspace_of(dir.to_path_buf(), new.clone());
        let report = analyze_workspace(&workspace, crate::git::DEFAULT_WINDOW_DAYS).unwrap();

        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(report.files.len(), 1);
        let ownership = &report.files[0];
        let by_email: std::collections::HashMap<_, _> = ownership
            .authors
            .iter()
            .map(|author| (author.email.as_str(), author.lines))
            .collect();
        assert_eq!(by_email.get("a@example.com"), Some(&3));
        assert_eq!(by_email.get("b@example.com"), Some(&2));
        assert_eq!(
            by_email.get("c@example.com"),
            None,
            "the rename-only commit must not be credited with any lines"
        );
    }

    /// Undecidable fixture (todo.md §17.5): two branches independently edit
    /// the same base line to the *same* resulting text, then merge. Since
    /// both parents' trees are byte-identical at the merge point, `git
    /// blame` — and, verified here, `gix`'s blame — never even looks at the
    /// second parent's history for that line: it credits whichever parent
    /// is checked first (`git merge`'s current-branch parent), not the
    /// "real" independent author of the identical text on the other
    /// branch. This isn't a bug: attributing a line that two people wrote
    /// identically, independently, to a single "true" author is genuinely
    /// undecidable from blame alone — `git blame` itself makes the same
    /// first-parent-wins choice (verified against the real CLI). Documented
    /// as a known ownership-data limitation, not fixed.
    #[test]
    fn merge_of_identical_independent_edits_credits_only_the_first_parents_author() {
        let dir = TempDir::new("ownership-merge-ambiguous");
        git(&dir, &["init", "-q", "-b", "main"]);

        let file = dir.join("f.rs");
        std::fs::write(&file, "line1\nline2\nline3\n").unwrap();
        run_git_as(&dir, "base@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "base@example.com",
            &["commit", "-q", "-m", "base"],
            &[],
        );

        git(&dir, &["checkout", "-q", "-b", "branch-x"]);
        std::fs::write(&file, "shared\nline2\nline3\n").unwrap();
        run_git_as(&dir, "x@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "x@example.com",
            &["commit", "-q", "-m", "x changes line1"],
            &[],
        );

        git(&dir, &["checkout", "-q", "main"]);
        git(&dir, &["checkout", "-q", "-b", "branch-y"]);
        // Same resulting text as branch-x, written independently.
        std::fs::write(&file, "shared\nline2\nline3\n").unwrap();
        run_git_as(&dir, "y@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "y@example.com",
            &["commit", "-q", "-m", "y changes line1 identically"],
            &[],
        );

        git(&dir, &["checkout", "-q", "branch-x"]);
        run_git_as(
            &dir,
            "merger@example.com",
            &["merge", "-q", "--no-edit", "branch-y", "-m", "merge"],
            &[],
        );

        let workspace = workspace_of(dir.to_path_buf(), file.clone());
        let report = analyze_workspace(&workspace, crate::git::DEFAULT_WINDOW_DAYS).unwrap();

        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(report.files.len(), 1);
        let ownership = &report.files[0];
        let by_email: std::collections::HashMap<_, _> = ownership
            .authors
            .iter()
            .map(|author| (author.email.as_str(), author.lines))
            .collect();
        assert_eq!(by_email.get("x@example.com"), Some(&1));
        assert_eq!(by_email.get("base@example.com"), Some(&2));
        assert_eq!(
            by_email.get("y@example.com"),
            None,
            "y's independent, identical edit is invisible to blame once merged"
        );
        assert_eq!(
            by_email.get("merger@example.com"),
            None,
            "a clean, non-conflicting merge commit is never itself a blame suspect"
        );
    }

    /// Undecidable fixture (todo.md §17.5): a single real person commits
    /// under two different email addresses (e.g. after switching employers
    /// or machines) with no `.mailmap` in the repository to unify them.
    /// `file_ownership` keys strictly by `author.email` (see its
    /// `lines_by_email` map), so this one person is counted as two
    /// authors — bus factor 2 instead of the true 1 — and `low-bus-factor`
    /// does not fire at all, a false negative on real knowledge
    /// concentration. This is a generic, well-known git-blame limitation
    /// (identity resolution needs a mailmap or external identity data, both
    /// out of scope here), not a bug in this rule's logic — documented, not
    /// fixed.
    #[test]
    fn same_person_with_two_emails_and_no_mailmap_is_double_counted_as_two_authors() {
        let dir = TempDir::new("ownership-split-identity");
        git(&dir, &["init", "-q", "-b", "main"]);

        let file = dir.join("solo.rs");
        std::fs::write(&file, "fn a() {}\nfn b() {}\n").unwrap();
        run_git_as(&dir, "solo.old@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "solo.old@example.com",
            &["commit", "-q", "-m", "first half, old email"],
            &[],
        );

        std::fs::write(&file, "fn a() {}\nfn b() {}\nfn c() {}\nfn d() {}\n").unwrap();
        run_git_as(&dir, "solo.new@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "solo.new@example.com",
            &["commit", "-q", "-m", "second half, new email"],
            &[],
        );

        let workspace = workspace_of(dir.to_path_buf(), file.clone());
        let report = analyze_workspace(&workspace, crate::git::DEFAULT_WINDOW_DAYS).unwrap();

        assert!(report.errors.is_empty(), "{:?}", report.errors);
        let ownership = &report.files[0];
        assert_eq!(
            ownership.authors.len(),
            2,
            "the same person's two emails are counted as two distinct authors: {:?}",
            ownership.authors
        );
        assert_eq!(
            ownership.bus_factor, 2,
            "the true bus factor is 1 (one person), but email-keyed blame reports 2"
        );
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.rule != LOW_BUS_FACTOR_RULE),
            "low-bus-factor false-negatives on this file because of the split identity: {:?}",
            report.findings
        );
    }

    #[test]
    fn ownership_error_source_preserves_the_underlying_error() {
        let err = OwnershipError::Blame(
            PathBuf::from("src/lib.rs"),
            Box::new(std::io::Error::other("boom")),
        );
        let source = std::error::Error::source(&err).expect("Blame must carry a source");
        assert!(source.downcast_ref::<std::io::Error>().is_some());
        assert_eq!(err.to_string(), "src/lib.rs: failed to blame file: boom");
    }
}
