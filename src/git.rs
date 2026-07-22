//! Git signals: file churn, computed via `gix` — no `git` subprocess (see
//! todo.md §2, §3.E).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use gix::bstr::ByteSlice;

use crate::complexity::FunctionInfo;
use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::ingest::Workspace;

/// Default lookback window for churn: 12 months.
pub const DEFAULT_WINDOW_DAYS: i64 = 365;

/// Rule id used for [`Hotspot`] findings (see todo.md §3.E).
pub const HOTSPOT_RULE: &str = "hotspot";
/// Bump when the hotspot rule's logic changes, so a baseline taken under an
/// older revision doesn't silently protect findings from a real rule change
/// (see todo.md §5 "Regelversions-Schutz").
pub const HOTSPOT_RULE_REVISION: u32 = 1;

/// Rule id used for [`size_distribution`] findings (see todo.md §E
/// "Verteilungs-Audits: ... `size-distribution` (Gini über Dateigrößen,
/// 'God File')").
pub const SIZE_DISTRIBUTION_RULE: &str = "size-distribution";
/// Bump when the size-distribution rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const SIZE_DISTRIBUTION_RULE_REVISION: u32 = 1;

/// Minimum population Gini coefficient (see [`gini`]) over a crate's
/// authored-file LOC distribution for that crate's top-decile files to be
/// flagged as concentrated (see [`size_distribution`]). First-cut,
/// adjustable threshold — not yet backed by a distribution study of what
/// counts as normal file-size spread across real crates (mirrors
/// [`crate::duplication::DEFAULT_MIN_TOKENS`]'s arbitrary-but-documented
/// style).
pub const SIZE_DISTRIBUTION_GINI_THRESHOLD: f64 = 0.6;

#[derive(Debug)]
pub enum GitError {
    Open(Box<gix::open::Error>),
    Walk(Box<dyn std::error::Error + Send + Sync>),
    RevParse(String, Box<dyn std::error::Error + Send + Sync>),
    Status(Box<dyn std::error::Error + Send + Sync>),
    InvalidWindow(i64),
}

impl std::fmt::Display for GitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(err) => write!(f, "failed to open git repository: {err}"),
            Self::Walk(err) => write!(f, "failed to walk git history: {err}"),
            Self::RevParse(spec, err) => write!(f, "failed to resolve `{spec}`: {err}"),
            Self::Status(err) => write!(f, "failed to read repository status: {err}"),
            Self::InvalidWindow(days) => {
                write!(f, "invalid lookback window: {days} days (must be positive)")
            }
        }
    }
}

impl std::error::Error for GitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Open(err) => Some(err),
            Self::Walk(err) | Self::RevParse(_, err) | Self::Status(err) => Some(err.as_ref()),
            Self::InvalidWindow(_) => None,
        }
    }
}

impl From<gix::open::Error> for GitError {
    fn from(err: gix::open::Error) -> Self {
        Self::Open(Box::new(err))
    }
}

/// A validated, strictly positive lookback window in days (todo.md §15.1) —
/// the walks below never see a zero or negative window as a raw `i64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowDays(i64);

impl WindowDays {
    pub fn new(days: i64) -> Result<Self, GitError> {
        if days > 0 {
            Ok(Self(days))
        } else {
            Err(GitError::InvalidWindow(days))
        }
    }

    /// Unix-epoch cutoff for this window ending now: commits at or after
    /// this second are inside the window.
    fn cutoff_seconds(self) -> i64 {
        now_unix_seconds() - self.0 * 24 * 3600
    }
}

/// Time-ordered traversal that prunes commits older than `cutoff` inside
/// `gix` itself. Unlike the default breadth-first walk with a manual `break`
/// on the first too-old commit, this still visits a recent commit that is
/// only reachable through a merge's second parent behind an old first
/// parent (todo.md §15.1).
fn window_sorting(cutoff: i64) -> gix::revision::walk::Sorting {
    gix::revision::walk::Sorting::ByCommitTimeCutoff {
        order: gix::traverse::commit::simple::CommitTimeOrder::NewestFirst,
        seconds: cutoff,
    }
}

/// Number of commits touching each file within `window_days` of now, keyed
/// by path relative to the repository root. Commits are walked from HEAD;
/// an unborn HEAD (no commits yet) yields an empty map rather than an error.
pub fn churn(repo_root: &Path, window_days: i64) -> Result<HashMap<PathBuf, u32>, GitError> {
    let window = WindowDays::new(window_days)?;
    let repo = gix::open(repo_root)?;
    let mut counts = HashMap::new();

    let Ok(head_id) = repo.head_id() else {
        return Ok(counts);
    };

    let walk = repo
        .rev_walk(Some(head_id.detach()))
        .sorting(window_sorting(window.cutoff_seconds()))
        .all()
        .map_err(|err| GitError::Walk(err.into()))?;

    for info in walk {
        let info = info.map_err(|err| GitError::Walk(err.into()))?;
        let commit = info.object().map_err(|err| GitError::Walk(err.into()))?;

        let tree = commit.tree().map_err(|err| GitError::Walk(err.into()))?;
        let parent_tree = match commit.parent_ids().next() {
            Some(parent_id) => parent_id
                .object()
                .map_err(|err| GitError::Walk(err.into()))?
                .into_commit()
                .tree()
                .map_err(|err| GitError::Walk(err.into()))?,
            None => repo.empty_tree(),
        };

        parent_tree
            .changes()
            .map_err(|err| GitError::Walk(err.into()))?
            .for_each_to_obtain_tree(&tree, |change| {
                if let Some(path) = path_of(&change) {
                    *counts.entry(path).or_insert(0u32) += 1;
                }
                Ok::<_, std::convert::Infallible>(gix::object::tree::diff::Action::Continue(()))
            })
            .map_err(|err| GitError::Walk(err.into()))?;
    }

    Ok(counts)
}

/// One commit's metadata needed for provenance classification (see
/// `crate::provenance`, todo.md §3.G G6): author, timestamp, message
/// trailers/text, and the files it touched.
#[derive(Debug, Clone)]
pub struct CommitInfo {
    pub id: String,
    pub author_email: String,
    pub time: i64,
    pub trailers: Vec<(String, String)>,
    pub message_title: String,
    pub message_body: String,
    pub files_changed: Vec<PathBuf>,
}

/// Walks commits reachable from `HEAD` within `window_days` of now, in the
/// same cutoff/tree-diff shape as [`churn`], but returning full per-commit
/// metadata instead of a running file-touch count (see `crate::provenance`,
/// todo.md §3.G G6). Same unborn-HEAD tolerance as [`churn`]: an empty
/// `Vec`, not an error.
pub fn walk_commits(repo_root: &Path, window_days: i64) -> Result<Vec<CommitInfo>, GitError> {
    let window = WindowDays::new(window_days)?;
    let repo = gix::open(repo_root)?;
    let mut commits = Vec::new();

    let Ok(head_id) = repo.head_id() else {
        return Ok(commits);
    };

    let walk = repo
        .rev_walk(Some(head_id.detach()))
        .sorting(window_sorting(window.cutoff_seconds()))
        .all()
        .map_err(|err| GitError::Walk(err.into()))?;

    for info in walk {
        let info = info.map_err(|err| GitError::Walk(err.into()))?;
        let commit = info.object().map_err(|err| GitError::Walk(err.into()))?;
        let commit_time = commit
            .time()
            .map_err(|err| GitError::Walk(err.into()))?
            .seconds;

        let tree = commit.tree().map_err(|err| GitError::Walk(err.into()))?;
        let parent_tree = match commit.parent_ids().next() {
            Some(parent_id) => parent_id
                .object()
                .map_err(|err| GitError::Walk(err.into()))?
                .into_commit()
                .tree()
                .map_err(|err| GitError::Walk(err.into()))?,
            None => repo.empty_tree(),
        };

        let mut files_changed = Vec::new();
        parent_tree
            .changes()
            .map_err(|err| GitError::Walk(err.into()))?
            .for_each_to_obtain_tree(&tree, |change| {
                if let Some(path) = path_of(&change) {
                    files_changed.push(path);
                }
                Ok::<_, std::convert::Infallible>(gix::object::tree::diff::Action::Continue(()))
            })
            .map_err(|err| GitError::Walk(err.into()))?;

        let author = commit.author().map_err(|err| GitError::Walk(err.into()))?;
        let author_email = author.email.to_str_lossy().trim().to_string();

        let decoded = commit.decode().map_err(|err| GitError::Walk(err.into()))?;
        let trailers = decoded
            .attribution_trailers()
            .map(|trailer| {
                (
                    trailer.token.to_str_lossy().into_owned(),
                    trailer.value.to_str_lossy().into_owned(),
                )
            })
            .collect();

        let message = commit.message().map_err(|err| GitError::Walk(err.into()))?;
        let message_title = message.title.to_str_lossy().trim().to_string();
        let message_body = message
            .body
            .map(|body| body.to_str_lossy().trim().to_string())
            .unwrap_or_default();

        commits.push(CommitInfo {
            id: commit.id.to_string(),
            author_email,
            time: commit_time,
            trailers,
            message_title,
            message_body,
            files_changed,
        });
    }

    Ok(commits)
}

/// A file whose cyclomatic complexity and recent change frequency both stand
/// out — `complexity × changes` (see todo.md §3.E, §4).
#[derive(Debug, Clone)]
pub struct Hotspot {
    pub file: PathBuf,
    pub complexity: u32,
    pub changes: u32,
}

impl Hotspot {
    pub fn score(&self) -> u32 {
        self.complexity * self.changes
    }

    /// Renders this hotspot as a [`Finding`]. Severity is `Info`: there is no
    /// health-score threshold yet (see todo.md §4), so this is descriptive,
    /// not a pass/fail judgement. The evidence class is `heuristic`: churn
    /// and complexity counts are facts, but framing their product as risk
    /// is an interpretation (todo.md §17.3).
    pub fn to_finding(&self) -> Finding {
        Finding {
            id: format!("{HOTSPOT_RULE}:{}", self.file.display()).into(),
            rule: HOTSPOT_RULE.into(),
            severity: Severity::Info,
            location: Location {
                file: self.file.clone(),
                line: OneBasedLine::FIRST,
                item_path: self.file.display().to_string(),
            },
            evidence_class: EvidenceClass::Heuristic,
            origin: Origin::Code,
            evidence: None,
            caused_by: Vec::new(),
            causes: Vec::new(),
        }
    }
}

/// Combines per-function complexity with recent churn into hotspots, sorted
/// by score descending. Files with no recorded churn (or no git history at
/// all) are left out rather than shown as zero-risk.
pub fn hotspots(
    repo_root: &Path,
    functions: &[FunctionInfo],
    window_days: i64,
) -> Result<Vec<Hotspot>, GitError> {
    let churn_counts = churn(repo_root, window_days)?;

    let mut file_complexity: HashMap<PathBuf, u32> = HashMap::new();
    for function in functions {
        *file_complexity.entry(function.file.clone()).or_insert(0) += function.cyclomatic;
    }

    let mut hotspots: Vec<Hotspot> = file_complexity
        .into_iter()
        .filter_map(|(file, complexity)| {
            let relative = file.strip_prefix(repo_root).ok()?;
            let changes = *churn_counts.get(relative)?;
            (changes > 0).then_some(Hotspot {
                file,
                complexity,
                changes,
            })
        })
        .collect();
    hotspots.sort_by_key(|hotspot| std::cmp::Reverse(hotspot.score()));

    Ok(hotspots)
}

/// Population Gini coefficient over non-negative `values` (order-independent
/// — sorted internally): `0.0` (perfect equality) for `n <= 1` or an
/// all-zero/empty slice, since concentration is undefined without at least
/// two comparable, non-zero values to compare — not a divide-by-zero panic
/// (see [`size_distribution`]).
///
/// Given `values` sorted ascending `x_1 ≤ x_2 ≤ … ≤ x_n` (1-indexed) with `S
/// = Σx_i`: `G = (2 · Σ(i · x_i)) / (n · S) − (n + 1) / n`.
fn gini(values: &[u64]) -> f64 {
    if values.len() <= 1 {
        return 0.0;
    }

    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let sum: u64 = sorted.iter().sum();
    if sum == 0 {
        return 0.0;
    }

    let n = sorted.len() as f64;
    let weighted_sum: f64 = sorted
        .iter()
        .enumerate()
        .map(|(zero_based_index, &value)| (zero_based_index as f64 + 1.0) * value as f64)
        .sum();

    (2.0 * weighted_sum) / (n * sum as f64) - (n + 1.0) / n
}

/// Number of files in a crate's top LOC decile (top ~10%, by file count):
/// `file_count − floor(file_count × 0.9)`, computed via integer division to
/// avoid float rounding at the boundary. Always at least 1 for a non-empty
/// crate (see [`size_distribution`]).
fn top_decile_count(file_count: usize) -> usize {
    file_count - (file_count * 9 / 10)
}

/// A file whose LOC lands in its crate's top decile while that crate's own
/// file-size distribution is concentrated (Gini coefficient above
/// [`SIZE_DISTRIBUTION_GINI_THRESHOLD`]) — see [`size_distribution`].
#[derive(Debug, Clone)]
pub struct SizeDistributionOutlier {
    pub file: PathBuf,
    pub loc: u64,
    pub crate_name: String,
    pub crate_gini: f64,
    pub crate_file_count: usize,
}

impl SizeDistributionOutlier {
    /// Renders this outlier as a [`Finding`]. Severity is `Info` and the
    /// evidence class is `Heuristic`, mirroring [`Hotspot::to_finding`]:
    /// this repo's own `main.rs` is large and would trip almost any flat
    /// "God File" line-count threshold, yet a large, concentrated file is
    /// routinely legitimate (a CLI dispatch table, an enum-heavy config
    /// module), so this must never gate. The wording states only the LOC,
    /// crate, file count, and Gini coefficient — never that the file "is too
    /// big" or "needs refactoring" (todo.md §17.4).
    pub fn to_finding(&self) -> Finding {
        Finding {
            id: format!("{SIZE_DISTRIBUTION_RULE}:{}", self.file.display()).into(),
            rule: SIZE_DISTRIBUTION_RULE.into(),
            severity: Severity::Info,
            location: Location {
                file: self.file.clone(),
                line: OneBasedLine::FIRST,
                item_path: self.file.display().to_string(),
            },
            evidence_class: EvidenceClass::Heuristic,
            origin: Origin::Code,
            evidence: Some(serde_json::json!({
                "lines_of_code": self.loc,
                "crate": self.crate_name,
                "crate_file_count": self.crate_file_count,
                "crate_gini": self.crate_gini,
                "gini_threshold": SIZE_DISTRIBUTION_GINI_THRESHOLD,
                "reason": format!(
                    "this file has {} lines of code, in the top decile for crate `{}` ({} authored files), whose file-size distribution has a Gini coefficient of {:.2} (threshold: {SIZE_DISTRIBUTION_GINI_THRESHOLD})",
                    self.loc, self.crate_name, self.crate_file_count, self.crate_gini
                ),
            })),
            caused_by: Vec::new(),
            causes: Vec::new(),
        }
    }
}

/// Per workspace crate, flags authored files whose LOC lands in that crate's
/// top decile (top ~10% by file count, see [`top_decile_count`]) when the
/// crate's own authored-file LOC distribution is concentrated — Gini
/// coefficient (see [`gini`]) above [`SIZE_DISTRIBUTION_GINI_THRESHOLD`].
/// Both conditions are required: a bare large-file LOC number alone says
/// nothing about concentration, and the crate-level Gini gate is what makes
/// this a distribution claim rather than an arbitrary LOC cutoff.
///
/// Needs no git history at all — pure per-file LOC plus per-crate
/// aggregation over the already-loaded [`Workspace`] — unlike [`hotspots`],
/// which needs `churn`'s git walk.
///
/// A crate with only one authored file always has Gini `0.0` (the `n <= 1`
/// edge case in [`gini`]), so it never fires — correct, since concentration
/// requires more than one file to compare against, not a bug. An unreadable
/// file is silently skipped, matching [`crate::health_score::total_authored_loc`]'s
/// tolerance.
pub fn size_distribution(workspace: &Workspace) -> Vec<SizeDistributionOutlier> {
    let mut outliers = Vec::new();

    for krate in &workspace.crates {
        let mut file_locs: Vec<(PathBuf, u64)> = krate
            .source_files
            .iter()
            .filter(|file| file.kind.is_locally_reportable())
            .filter_map(|file| {
                std::fs::read_to_string(&file.path)
                    .ok()
                    .map(|content| (file.path.clone(), content.lines().count() as u64))
            })
            .collect();
        if file_locs.is_empty() {
            continue;
        }

        let loc_values: Vec<u64> = file_locs.iter().map(|(_, loc)| *loc).collect();
        let crate_gini = gini(&loc_values);
        if crate_gini <= SIZE_DISTRIBUTION_GINI_THRESHOLD {
            continue;
        }

        file_locs.sort_by_key(|(_, loc)| std::cmp::Reverse(*loc));
        let crate_file_count = file_locs.len();
        let flagged_count = top_decile_count(crate_file_count);

        outliers.extend(
            file_locs
                .into_iter()
                .take(flagged_count)
                .map(|(file, loc)| SizeDistributionOutlier {
                    file,
                    loc,
                    crate_name: krate.name.clone(),
                    crate_gini,
                    crate_file_count,
                }),
        );
    }

    outliers
}

/// The current `HEAD` commit as a full hex object id (see todo.md §5,
/// `first_seen_commit`).
pub fn head_commit(repo_root: &Path) -> Result<String, GitError> {
    let repo = gix::open(repo_root)?;
    let head_id = repo.head_id().map_err(|err| GitError::Walk(err.into()))?;
    Ok(head_id.to_string())
}

/// Resolves `spec` (a commit-ish — branch, tag, or short/long sha) to its
/// full hex object id (see `audit --since`, todo.md §5).
pub fn resolve_commit(repo_root: &Path, spec: &str) -> Result<String, GitError> {
    let repo = gix::open(repo_root)?;
    let id = repo
        .rev_parse_single(spec)
        .map_err(|err| GitError::RevParse(spec.to_string(), err.into()))?;
    Ok(id.to_string())
}

/// Whether `ancestor` is reachable from `descendant` — i.e. `descendant`'s
/// history contains `ancestor` (equal commits count as ancestors of
/// themselves). Used to guard `audit --since` against a saved baseline that
/// has diverged from the requested `<ref>` (see todo.md §5): a genuinely
/// diverged baseline must not silently produce a misleading delta.
pub fn is_ancestor(repo_root: &Path, ancestor: &str, descendant: &str) -> Result<bool, GitError> {
    let repo = gix::open(repo_root)?;
    let ancestor_id = repo
        .rev_parse_single(ancestor)
        .map_err(|err| GitError::RevParse(ancestor.to_string(), err.into()))?
        .detach();
    let descendant_id = repo
        .rev_parse_single(descendant)
        .map_err(|err| GitError::RevParse(descendant.to_string(), err.into()))?
        .detach();

    if ancestor_id == descendant_id {
        return Ok(true);
    }

    match repo.merge_base(ancestor_id, descendant_id) {
        Ok(base) => Ok(base.detach() == ancestor_id),
        Err(gix::repository::merge_base::Error::NotFound { .. }) => Ok(false),
        Err(err) => Err(GitError::Walk(err.into())),
    }
}

/// Files that differ between `since_commit` and the current checkout,
/// relative to `repo_root`. This includes committed changes through `HEAD`,
/// staged changes, unstaged changes, and untracked files.
pub fn changed_files_since(
    repo_root: &Path,
    since_commit: &str,
) -> Result<std::collections::HashSet<PathBuf>, GitError> {
    let repo = gix::open(repo_root)?;
    let since_id = repo
        .rev_parse_single(since_commit)
        .map_err(|err| GitError::RevParse(since_commit.to_string(), err.into()))?;
    let head_id = repo.head_id().map_err(|err| GitError::Walk(err.into()))?;

    let since_tree = since_id
        .object()
        .map_err(|err| GitError::Walk(err.into()))?
        .into_commit()
        .tree()
        .map_err(|err| GitError::Walk(err.into()))?;
    let head_tree = head_id
        .object()
        .map_err(|err| GitError::Walk(err.into()))?
        .into_commit()
        .tree()
        .map_err(|err| GitError::Walk(err.into()))?;

    let mut changed = std::collections::HashSet::new();
    since_tree
        .changes()
        .map_err(|err| GitError::Walk(err.into()))?
        .for_each_to_obtain_tree(&head_tree, |change| {
            if let Some(path) = path_of(&change) {
                changed.insert(path);
            }
            Ok::<_, std::convert::Infallible>(gix::object::tree::diff::Action::Continue(()))
        })
        .map_err(|err| GitError::Walk(err.into()))?;

    let status = repo
        .status(gix::progress::Discard)
        .map_err(|err| GitError::Status(err.into()))?
        .untracked_files(gix::status::UntrackedFiles::Files);
    let status_items = status
        .into_iter(Vec::<gix::bstr::BString>::new())
        .map_err(|err| GitError::Status(err.into()))?;
    for item in status_items {
        let item = item.map_err(|err| GitError::Status(err.into()))?;
        let location = item.location();
        if !location.is_empty() {
            changed.insert(PathBuf::from(location.to_str_lossy().into_owned()));
        }
    }

    Ok(changed)
}

/// Email addresses of everyone who committed anywhere in the repo within
/// `window_days` of now (see todo.md §3.E `knowledge-loss-risk` — this is
/// "is this person still around at all", not per-file). Commits are walked
/// from HEAD; an unborn HEAD (no commits yet) yields an empty set rather
/// than an error, matching [`churn`]'s tolerance.
pub fn active_authors_since(
    repo_root: &Path,
    window_days: i64,
) -> Result<HashSet<String>, GitError> {
    let window = WindowDays::new(window_days)?;
    let repo = gix::open(repo_root)?;
    let mut authors = HashSet::new();

    let Ok(head_id) = repo.head_id() else {
        return Ok(authors);
    };

    let walk = repo
        .rev_walk(Some(head_id.detach()))
        .sorting(window_sorting(window.cutoff_seconds()))
        .all()
        .map_err(|err| GitError::Walk(err.into()))?;

    for info in walk {
        let info = info.map_err(|err| GitError::Walk(err.into()))?;
        let commit = info.object().map_err(|err| GitError::Walk(err.into()))?;

        let author = commit.author().map_err(|err| GitError::Walk(err.into()))?;
        authors.insert(author.email.to_str_lossy().trim().to_string());
    }

    Ok(authors)
}

/// A tree diff reports a change for every entry that differs, including
/// directories themselves (e.g. adding a new subdirectory full of files
/// yields both an `Addition` for the directory *and* one for each file
/// inside it) — `entry_mode` distinguishes them. Without this filter,
/// `churn`/`changed_files_since` would treat a directory path as if it were
/// a changed file.
fn path_of(change: &gix::object::tree::diff::Change<'_, '_, '_>) -> Option<PathBuf> {
    if !change.entry_mode().is_blob_or_symlink() {
        return None;
    }
    let location = change.location();
    if location.is_empty() {
        return None;
    }
    Some(PathBuf::from(location.to_str_lossy().into_owned()))
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    /// Runs `git` in `dir` with a fixed test identity, so these tests don't
    /// depend on the host's global git config being set up.
    fn git(dir: &Path, args: &[&str]) {
        run_git(dir, args, &[]);
    }

    fn run_git(dir: &Path, args: &[&str], extra_env: &[(&str, &str)]) {
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

    #[test]
    fn churn_counts_commits_touching_each_file() {
        let dir = TempDir::new("git-churn");
        git(&dir, &["init", "-q", "-b", "main"]);

        std::fs::write(dir.join("a.rs"), "fn a() {}\n").unwrap();
        std::fs::write(dir.join("b.rs"), "fn b() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);

        std::fs::write(dir.join("a.rs"), "fn a() { 1 }\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "touch a again"]);

        let counts = churn(&dir, DEFAULT_WINDOW_DAYS).unwrap();

        assert_eq!(counts.get(&PathBuf::from("a.rs")), Some(&2));
        assert_eq!(counts.get(&PathBuf::from("b.rs")), Some(&1));
    }

    #[test]
    fn churn_does_not_count_a_newly_added_directory_as_a_file() {
        let dir = TempDir::new("git-churn-new-dir");
        git(&dir, &["init", "-q", "-b", "main"]);
        git(&dir, &["commit", "-q", "--allow-empty", "-m", "initial"]);

        std::fs::create_dir_all(dir.join("newdir")).unwrap();
        std::fs::write(dir.join("newdir/a.rs"), "fn a() {}\n").unwrap();
        std::fs::write(dir.join("newdir/b.rs"), "fn b() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "add newdir"]);

        let counts = churn(&dir, DEFAULT_WINDOW_DAYS).unwrap();

        assert_eq!(counts.get(&PathBuf::from("newdir")), None);
        assert_eq!(counts.get(&PathBuf::from("newdir/a.rs")), Some(&1));
        assert_eq!(counts.get(&PathBuf::from("newdir/b.rs")), Some(&1));
    }

    #[test]
    fn churn_returns_empty_map_for_repo_without_commits() {
        let dir = TempDir::new("git-no-commits");
        git(&dir, &["init", "-q", "-b", "main"]);

        let counts = churn(&dir, DEFAULT_WINDOW_DAYS).unwrap();
        assert!(counts.is_empty());
    }

    #[test]
    fn churn_errors_for_a_non_repository() {
        let dir = TempDir::new("git-not-a-repo");

        let err = churn(&dir, DEFAULT_WINDOW_DAYS).unwrap_err();
        assert!(matches!(err, GitError::Open(_)));
    }

    #[test]
    fn churn_ignores_commits_outside_the_window() {
        let dir = TempDir::new("git-old-commit");
        git(&dir, &["init", "-q", "-b", "main"]);

        let old_date = [
            ("GIT_AUTHOR_DATE", "2000-01-01T00:00:00"),
            ("GIT_COMMITTER_DATE", "2000-01-01T00:00:00"),
        ];
        std::fs::write(dir.join("old.rs"), "fn old() {}\n").unwrap();
        run_git(&dir, &["add", "."], &[]);
        run_git(&dir, &["commit", "-q", "-m", "ancient"], &old_date);

        std::fs::write(dir.join("new.rs"), "fn new() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "recent"]);

        let counts = churn(&dir, 30).unwrap();

        assert_eq!(counts.get(&PathBuf::from("new.rs")), Some(&1));
        assert_eq!(counts.get(&PathBuf::from("old.rs")), None);
    }

    #[test]
    fn walk_commits_parses_a_co_authored_by_trailer() {
        let dir = TempDir::new("git-walk-commits-trailer");
        git(&dir, &["init", "-q", "-b", "main"]);

        std::fs::write(dir.join("a.rs"), "fn a() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(
            &dir,
            &[
                "commit",
                "-q",
                "-m",
                "add a\n\nCo-authored-by: Claude <noreply@anthropic.com>",
            ],
        );

        let commits = walk_commits(&dir, DEFAULT_WINDOW_DAYS).unwrap();

        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].message_title, "add a");
        assert_eq!(
            commits[0].trailers,
            vec![(
                "Co-authored-by".to_string(),
                "Claude <noreply@anthropic.com>".to_string()
            )]
        );
        assert_eq!(commits[0].files_changed, vec![PathBuf::from("a.rs")]);
    }

    #[test]
    fn walk_commits_returns_empty_trailers_for_a_plain_commit() {
        let dir = TempDir::new("git-walk-commits-no-trailer");
        git(&dir, &["init", "-q", "-b", "main"]);

        std::fs::write(dir.join("a.rs"), "fn a() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "add a"]);

        let commits = walk_commits(&dir, DEFAULT_WINDOW_DAYS).unwrap();

        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].message_title, "add a");
        assert!(commits[0].trailers.is_empty());
    }

    #[test]
    fn walk_commits_ignores_commits_outside_the_window() {
        let dir = TempDir::new("git-walk-commits-window");
        git(&dir, &["init", "-q", "-b", "main"]);

        let old_date = [
            ("GIT_AUTHOR_DATE", "2000-01-01T00:00:00"),
            ("GIT_COMMITTER_DATE", "2000-01-01T00:00:00"),
        ];
        std::fs::write(dir.join("old.rs"), "fn old() {}\n").unwrap();
        run_git(&dir, &["add", "."], &[]);
        run_git(&dir, &["commit", "-q", "-m", "ancient"], &old_date);

        std::fs::write(dir.join("new.rs"), "fn new() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "recent"]);

        let commits = walk_commits(&dir, 30).unwrap();

        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].message_title, "recent");
    }

    #[test]
    fn walk_commits_returns_empty_vec_for_repo_without_commits() {
        let dir = TempDir::new("git-walk-commits-no-commits");
        git(&dir, &["init", "-q", "-b", "main"]);

        let commits = walk_commits(&dir, DEFAULT_WINDOW_DAYS).unwrap();
        assert!(commits.is_empty());
    }

    fn function_info(file: PathBuf, cyclomatic: u32) -> FunctionInfo {
        FunctionInfo {
            qualified_name: "f".to_string(),
            file,
            line: 1,
            cyclomatic,
            lines_of_code: 1,
            nesting_depth: 0,
            match_arm_count: 0,
            arg_count: 0,
        }
    }

    #[test]
    fn hotspots_combines_complexity_and_churn_and_sorts_by_score() {
        let dir = TempDir::new("git-hotspots");
        git(&dir, &["init", "-q", "-b", "main"]);

        std::fs::write(dir.join("hot.rs"), "fn hot() {}\n").unwrap();
        std::fs::write(dir.join("cold.rs"), "fn cold() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);

        std::fs::write(dir.join("hot.rs"), "fn hot() { 1 }\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "touch hot again"]);

        let functions = vec![
            function_info(dir.join("hot.rs"), 10),
            function_info(dir.join("cold.rs"), 3),
        ];

        let found = hotspots(&dir, &functions, DEFAULT_WINDOW_DAYS).unwrap();

        assert_eq!(found.len(), 2);
        assert_eq!(found[0].file, dir.join("hot.rs"));
        assert_eq!(found[0].complexity, 10);
        assert_eq!(found[0].changes, 2);
        assert_eq!(found[0].score(), 20);
        assert_eq!(found[1].file, dir.join("cold.rs"));
        assert_eq!(found[1].score(), 3);
    }

    #[test]
    fn hotspots_skips_files_with_no_recorded_churn() {
        let dir = TempDir::new("git-hotspots-no-churn");
        git(&dir, &["init", "-q", "-b", "main"]);

        let functions = vec![function_info(dir.join("never_committed.rs"), 42)];
        let found = hotspots(&dir, &functions, DEFAULT_WINDOW_DAYS).unwrap();

        assert!(found.is_empty());
    }

    /// `hotspots()` calls the same [`churn`] that `churn-hotspot`
    /// (`slop_structural::churn_hotspot`) reads, and `churn` has no rename
    /// tracking configured on its tree diff. A `git mv` with no content
    /// change is therefore split into a `Deletion` under the old path and an
    /// `Addition` under the new one, rather than fused into one history —
    /// already confirmed as a real, non-fixed undercounting limit for
    /// `churn-hotspot` (todo.md §17.5, 2026-07-19 entry). Since `hotspots()`
    /// looks up churn by the file's *current* path only (the path
    /// `FunctionInfo` carries, from parsing the checkout as it exists now),
    /// the same split applies to the `hotspot` score itself: the 3 commits
    /// that touched `old.rs` before the rename are invisible to the score,
    /// even though the file (under its new name) really has 6 real touches.
    #[test]
    fn hotspots_score_only_counts_churn_after_an_untracked_rename() {
        let dir = TempDir::new("git-hotspots-rename-split");
        git(&dir, &["init", "-q", "-b", "main"]);

        std::fs::write(dir.join("old.rs"), "fn f() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);

        std::fs::write(dir.join("old.rs"), "fn f() { 1 }\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "touch old 1"]);

        std::fs::write(dir.join("old.rs"), "fn f() { 2 }\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "touch old 2"]);

        git(&dir, &["mv", "old.rs", "new.rs"]);
        git(&dir, &["commit", "-q", "-m", "rename old to new"]);

        std::fs::write(dir.join("new.rs"), "fn f() { 3 }\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "touch new 1"]);

        std::fs::write(dir.join("new.rs"), "fn f() { 4 }\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "touch new 2"]);

        // The file (as it exists today) really was touched 6 times, but the
        // rename splits that into 3 commits under `old.rs` and 3 under
        // `new.rs` — see `churn`'s direct count below.
        let churn_counts = churn(&dir, DEFAULT_WINDOW_DAYS).unwrap();
        assert_eq!(churn_counts.get(&PathBuf::from("old.rs")), Some(&3));
        assert_eq!(churn_counts.get(&PathBuf::from("new.rs")), Some(&3));

        let functions = vec![function_info(dir.join("new.rs"), 5)];
        let found = hotspots(&dir, &functions, DEFAULT_WINDOW_DAYS).unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].file, dir.join("new.rs"));
        // Only the post-rename half of the file's real history is visible
        // to the hotspot score.
        assert_eq!(found[0].changes, 3);
        assert_eq!(found[0].score(), 15);
    }

    /// A file that had heavy churn but no longer exists in the checkout is
    /// correctly left out of hotspots — not shown as a spurious
    /// complexity-0 entry. This falls out of how `hotspots()` is driven: the
    /// candidate set is `file_complexity`, built purely from the caller's
    /// `functions` (parsed from files that exist on disk today), and
    /// `churn` is only ever used to look values up for keys already in that
    /// set. A file with churn but no matching `FunctionInfo` (because a real
    /// caller can't parse a file that no longer exists) never enters the
    /// candidate set in the first place.
    #[test]
    fn hotspots_excludes_a_deleted_file_even_though_it_had_heavy_churn() {
        let dir = TempDir::new("git-hotspots-deleted-file");
        git(&dir, &["init", "-q", "-b", "main"]);

        std::fs::write(dir.join("deleted.rs"), "fn f() {}\n").unwrap();
        std::fs::write(dir.join("kept.rs"), "fn g() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);

        std::fs::write(dir.join("deleted.rs"), "fn f() { 1 }\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "touch deleted 1"]);

        std::fs::write(dir.join("deleted.rs"), "fn f() { 2 }\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "touch deleted 2"]);

        git(&dir, &["rm", "-q", "deleted.rs"]);
        git(&dir, &["commit", "-q", "-m", "remove deleted.rs"]);

        // `deleted.rs` really has 4 recorded churn touches (3 edits + the
        // removal), more than `kept.rs` — but no `FunctionInfo` for it,
        // matching what a real caller would produce.
        let churn_counts = churn(&dir, DEFAULT_WINDOW_DAYS).unwrap();
        assert_eq!(churn_counts.get(&PathBuf::from("deleted.rs")), Some(&4));

        let functions = vec![function_info(dir.join("kept.rs"), 5)];
        let found = hotspots(&dir, &functions, DEFAULT_WINDOW_DAYS).unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].file, dir.join("kept.rs"));
    }

    /// todo.md §3.E describes the hotspot formula as `Komplexität ×
    /// Änderungsfrequenz (... exponentielle Gewichtung neuerer Commits)`,
    /// but `Hotspot::score` is a flat `complexity * changes` and `changes`
    /// is `churn`'s raw commit count inside the window — no recency
    /// weighting is implemented. This test documents that gap: a file
    /// touched only near the far edge of the window scores identically to
    /// one touched the same number of times, but only very recently.
    #[test]
    fn hotspots_score_has_no_recency_weighting_despite_the_docs() {
        let dir = TempDir::new("git-hotspots-no-recency-weight");
        git(&dir, &["init", "-q", "-b", "main"]);
        git(&dir, &["commit", "-q", "--allow-empty", "-m", "root"]);

        // Just inside the default 365-day window, but as old as it gets
        // without falling out of it.
        let far_edge_date = unix_date_env(300);
        let far_edge = [
            ("GIT_AUTHOR_DATE", far_edge_date.as_str()),
            ("GIT_COMMITTER_DATE", far_edge_date.as_str()),
        ];
        std::fs::write(dir.join("old_edge.rs"), "fn f() {}\n").unwrap();
        run_git(&dir, &["add", "."], &[]);
        run_git(&dir, &["commit", "-q", "-m", "old edge 1"], &far_edge);
        std::fs::write(dir.join("old_edge.rs"), "fn f() { 1 }\n").unwrap();
        run_git(&dir, &["add", "."], &[]);
        run_git(&dir, &["commit", "-q", "-m", "old edge 2"], &far_edge);
        std::fs::write(dir.join("old_edge.rs"), "fn f() { 2 }\n").unwrap();
        run_git(&dir, &["add", "."], &[]);
        run_git(&dir, &["commit", "-q", "-m", "old edge 3"], &far_edge);

        std::fs::write(dir.join("recent.rs"), "fn g() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "recent 1"]);
        std::fs::write(dir.join("recent.rs"), "fn g() { 1 }\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "recent 2"]);
        std::fs::write(dir.join("recent.rs"), "fn g() { 2 }\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "recent 3"]);

        let functions = vec![
            function_info(dir.join("old_edge.rs"), 5),
            function_info(dir.join("recent.rs"), 5),
        ];
        let found = hotspots(&dir, &functions, DEFAULT_WINDOW_DAYS).unwrap();

        assert_eq!(found.len(), 2);
        let old_edge = found
            .iter()
            .find(|hotspot| hotspot.file == dir.join("old_edge.rs"))
            .unwrap();
        let recent = found
            .iter()
            .find(|hotspot| hotspot.file == dir.join("recent.rs"))
            .unwrap();
        assert_eq!(old_edge.changes, 3);
        assert_eq!(recent.changes, 3);
        // Same complexity, same raw commit count, wildly different recency
        // — yet identical score, because no exponential weighting exists.
        assert_eq!(old_edge.score(), recent.score());
    }

    /// Formats a Unix timestamp `days_ago` days before "now" the way `git`
    /// accepts for `GIT_AUTHOR_DATE`/`GIT_COMMITTER_DATE` (`@<seconds>
    /// <tz-offset>`), for tests that need a commit date near, but still
    /// inside, a lookback window's far edge (unlike the fixed year-2000
    /// dates other tests use for dates meant to fall *outside* the window).
    fn unix_date_env(days_ago: i64) -> String {
        let seconds = now_unix_seconds() - days_ago * 24 * 3600;
        format!("@{seconds} +0000")
    }

    #[test]
    fn hotspot_to_finding_is_informational_and_stable() {
        let hotspot = Hotspot {
            file: PathBuf::from("src/lib.rs"),
            complexity: 5,
            changes: 2,
        };
        let finding = hotspot.to_finding();

        assert_eq!(finding.rule, HOTSPOT_RULE);
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.location.file, PathBuf::from("src/lib.rs"));
    }

    #[test]
    fn gini_is_zero_for_perfect_equality() {
        assert_eq!(gini(&[1, 1, 1, 1]), 0.0);
    }

    #[test]
    fn gini_approaches_the_n_minus_one_over_n_bound_for_maximal_inequality() {
        // One file holds everything, the rest are empty: the most unequal
        // distribution representable — should land close to `(n-1)/n`.
        let values = [0, 0, 0, 100];
        let g = gini(&values);
        assert!((g - 0.75).abs() < 1e-9, "expected ~0.75, got {g}");
    }

    #[test]
    fn gini_is_zero_for_an_empty_slice() {
        assert_eq!(gini(&[]), 0.0);
    }

    #[test]
    fn gini_is_zero_for_a_single_value() {
        assert_eq!(gini(&[42]), 0.0);
    }

    #[test]
    fn gini_is_zero_when_every_value_is_zero() {
        assert_eq!(gini(&[0, 0, 0]), 0.0);
    }

    /// Builds a single-crate `Workspace` rooted at `dir`, with one authored
    /// `SourceFile` per `(relative_path, line_count)` pair — each file
    /// written with exactly that many lines, matching how [`size_distribution`]
    /// counts LOC (`content.lines().count()`).
    fn workspace_with_sized_files(
        dir: &Path,
        crate_name: &str,
        files: &[(&str, usize)],
    ) -> Workspace {
        let mut source_files = Vec::new();
        for (relative_path, line_count) in files {
            let path = dir.join(relative_path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            let content = "x\n".repeat(*line_count);
            std::fs::write(&path, content).unwrap();
            source_files.push(crate::ingest::SourceFile {
                path,
                kind: crate::ingest::SourceKind::Authored,
            });
        }

        Workspace {
            root: dir.to_path_buf(),
            crates: vec![crate::ingest::CrateInfo {
                name: crate_name.to_string(),
                version: "0.1.0".to_string(),
                manifest_path: dir.join("Cargo.toml"),
                root: dir.to_path_buf(),
                source_files,
                entry_points: Vec::new(),
                dependencies: Vec::new(),
            }],
        }
    }

    #[test]
    fn size_distribution_flags_the_top_decile_file_of_a_concentrated_crate() {
        let dir = TempDir::new("size-distribution-concentrated");
        let workspace = workspace_with_sized_files(
            &dir,
            "concentrated",
            &[
                ("src/huge.rs", 1000),
                ("src/small_a.rs", 10),
                ("src/small_b.rs", 10),
                ("src/small_c.rs", 10),
                ("src/small_d.rs", 10),
            ],
        );

        let outliers = size_distribution(&workspace);

        assert_eq!(outliers.len(), 1);
        assert_eq!(outliers[0].file, dir.join("src/huge.rs"));
        assert_eq!(outliers[0].loc, 1000);
        assert_eq!(outliers[0].crate_name, "concentrated");
        assert_eq!(outliers[0].crate_file_count, 5);
        assert!(outliers[0].crate_gini > SIZE_DISTRIBUTION_GINI_THRESHOLD);
    }

    #[test]
    fn size_distribution_does_not_fire_for_uniformly_sized_files() {
        let dir = TempDir::new("size-distribution-uniform");
        let workspace = workspace_with_sized_files(
            &dir,
            "uniform",
            &[
                ("src/a.rs", 100),
                ("src/b.rs", 100),
                ("src/c.rs", 100),
                ("src/d.rs", 105),
            ],
        );

        let outliers = size_distribution(&workspace);

        assert!(
            outliers.is_empty(),
            "expected no outliers for a near-uniform crate, got {outliers:?}"
        );
    }

    #[test]
    fn size_distribution_never_fires_for_a_single_file_crate() {
        let dir = TempDir::new("size-distribution-single-file");
        let workspace = workspace_with_sized_files(&dir, "solo", &[("src/lib.rs", 5000)]);

        let outliers = size_distribution(&workspace);

        assert!(outliers.is_empty());
    }

    #[test]
    fn size_distribution_handles_a_crate_with_no_authored_files() {
        let dir = TempDir::new("size-distribution-no-files");
        let workspace = workspace_with_sized_files(&dir, "empty", &[]);

        let outliers = size_distribution(&workspace);

        assert!(outliers.is_empty());
    }

    #[test]
    fn size_distribution_to_finding_states_facts_not_a_verdict() {
        let outlier = SizeDistributionOutlier {
            file: PathBuf::from("src/main.rs"),
            loc: 2000,
            crate_name: "judge".to_string(),
            crate_gini: 0.72,
            crate_file_count: 12,
        };
        let finding = outlier.to_finding();

        assert_eq!(finding.rule, SIZE_DISTRIBUTION_RULE);
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.evidence_class, EvidenceClass::Heuristic);
        assert_eq!(finding.location.file, PathBuf::from("src/main.rs"));
        let evidence = finding.evidence.expect("evidence must be populated");
        assert_eq!(evidence["lines_of_code"], 2000);
        assert_eq!(evidence["crate"], "judge");
        assert_eq!(evidence["crate_file_count"], 12);
    }

    fn commit_sha(dir: &Path, rev: &str) -> String {
        let output = std::process::Command::new("git")
            .args(["rev-parse", rev])
            .current_dir(dir)
            .output()
            .expect("failed to run git rev-parse");
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    #[test]
    fn head_commit_matches_git_rev_parse() {
        let dir = TempDir::new("git-head-commit");
        git(&dir, &["init", "-q", "-b", "main"]);
        std::fs::write(dir.join("a.rs"), "fn a() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);

        assert_eq!(head_commit(&dir).unwrap(), commit_sha(&dir, "HEAD"));
    }

    #[test]
    fn changed_files_since_reports_only_files_touched_after_the_given_commit() {
        let dir = TempDir::new("git-changed-since");
        git(&dir, &["init", "-q", "-b", "main"]);

        std::fs::write(dir.join("a.rs"), "fn a() {}\n").unwrap();
        std::fs::write(dir.join("b.rs"), "fn b() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);
        let baseline_commit = commit_sha(&dir, "HEAD");

        std::fs::write(dir.join("a.rs"), "fn a() { 1 }\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "touch a"]);

        let changed = changed_files_since(&dir, &baseline_commit).unwrap();

        assert!(changed.contains(&PathBuf::from("a.rs")));
        assert!(!changed.contains(&PathBuf::from("b.rs")));
    }

    #[test]
    fn changed_files_since_includes_staged_unstaged_and_untracked_files() {
        let dir = TempDir::new("git-changed-worktree");
        git(&dir, &["init", "-q", "-b", "main"]);
        std::fs::write(dir.join("staged.rs"), "fn staged() {}\n").unwrap();
        std::fs::write(dir.join("unstaged.rs"), "fn unstaged() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);
        let baseline_commit = commit_sha(&dir, "HEAD");

        std::fs::write(dir.join("staged.rs"), "fn staged() { 1 }\n").unwrap();
        git(&dir, &["add", "staged.rs"]);
        std::fs::write(dir.join("unstaged.rs"), "fn unstaged() { 1 }\n").unwrap();
        std::fs::write(dir.join("untracked.rs"), "fn untracked() {}\n").unwrap();

        let changed = changed_files_since(&dir, &baseline_commit).unwrap();

        assert!(changed.contains(&PathBuf::from("staged.rs")));
        assert!(changed.contains(&PathBuf::from("unstaged.rs")));
        assert!(changed.contains(&PathBuf::from("untracked.rs")));
    }

    /// Like [`run_git`], but with a caller-supplied author identity instead
    /// of the fixed `judge-test` one — needed to give different commits
    /// different author emails.
    fn run_git_as(dir: &Path, email: &str, args: &[&str], extra_env: &[(&str, &str)]) {
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

    /// History whose HEAD is a merge with an *ancient* first parent and a
    /// *recent* second parent:
    ///
    /// ```text
    /// ancient (old@, 2000) ------------- merge feature (merger@, now)
    ///        \                          /
    ///         feature work (feature@, now)
    /// ```
    ///
    /// The old breadth-first walk with a manual `break` visited `ancient`
    /// right after the merge and stopped, never reaching `feature work`.
    fn init_merge_with_old_first_parent(dir: &Path) {
        git(dir, &["init", "-q", "-b", "main"]);

        let old_date = [
            ("GIT_AUTHOR_DATE", "2000-01-01T00:00:00"),
            ("GIT_COMMITTER_DATE", "2000-01-01T00:00:00"),
        ];
        std::fs::write(dir.join("old.rs"), "fn old() {}\n").unwrap();
        run_git_as(dir, "old@example.com", &["add", "."], &[]);
        run_git_as(
            dir,
            "old@example.com",
            &["commit", "-q", "-m", "ancient"],
            &old_date,
        );

        git(dir, &["checkout", "-q", "-b", "feature"]);
        std::fs::write(dir.join("feature.rs"), "fn feature() {}\n").unwrap();
        run_git_as(dir, "feature@example.com", &["add", "."], &[]);
        run_git_as(
            dir,
            "feature@example.com",
            &["commit", "-q", "-m", "feature work"],
            &[],
        );

        git(dir, &["checkout", "-q", "main"]);
        run_git_as(
            dir,
            "merger@example.com",
            &["merge", "-q", "--no-ff", "feature", "-m", "merge feature"],
            &[],
        );
    }

    #[test]
    fn churn_counts_a_recent_second_parent_behind_an_old_first_parent() {
        let dir = TempDir::new("git-churn-merge-window");
        init_merge_with_old_first_parent(&dir);

        let counts = churn(&dir, 30).unwrap();

        // Once from the merge commit (diffed against its old first parent)
        // and once from the feature commit itself.
        assert_eq!(counts.get(&PathBuf::from("feature.rs")), Some(&2));
        assert_eq!(counts.get(&PathBuf::from("old.rs")), None);
    }

    #[test]
    fn active_authors_since_sees_a_recent_second_parent_behind_an_old_first_parent() {
        let dir = TempDir::new("git-authors-merge-window");
        init_merge_with_old_first_parent(&dir);

        let authors = active_authors_since(&dir, 30).unwrap();

        assert!(authors.contains("feature@example.com"));
        assert!(authors.contains("merger@example.com"));
        assert!(!authors.contains("old@example.com"));
    }

    #[test]
    fn walk_commits_sees_a_recent_second_parent_behind_an_old_first_parent() {
        let dir = TempDir::new("git-walk-commits-merge-window");
        init_merge_with_old_first_parent(&dir);

        let commits = walk_commits(&dir, 30).unwrap();
        let titles: Vec<&str> = commits
            .iter()
            .map(|commit| commit.message_title.as_str())
            .collect();

        assert!(titles.contains(&"feature work"));
        assert!(titles.contains(&"merge feature"));
        assert!(!titles.contains(&"ancient"));
    }

    #[test]
    fn a_non_positive_window_is_rejected() {
        let dir = TempDir::new("git-invalid-window");
        git(&dir, &["init", "-q", "-b", "main"]);

        assert!(matches!(
            churn(&dir, 0).unwrap_err(),
            GitError::InvalidWindow(0)
        ));
        assert!(matches!(
            walk_commits(&dir, 0).unwrap_err(),
            GitError::InvalidWindow(0)
        ));
        assert!(matches!(
            active_authors_since(&dir, -1).unwrap_err(),
            GitError::InvalidWindow(-1)
        ));
    }

    #[test]
    fn active_authors_since_includes_recent_and_excludes_old_authors() {
        let dir = TempDir::new("git-active-authors");
        git(&dir, &["init", "-q", "-b", "main"]);

        let old_date = [
            ("GIT_AUTHOR_DATE", "2000-01-01T00:00:00"),
            ("GIT_COMMITTER_DATE", "2000-01-01T00:00:00"),
        ];
        std::fs::write(dir.join("old.rs"), "fn old() {}\n").unwrap();
        run_git_as(&dir, "old@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "old@example.com",
            &["commit", "-q", "-m", "ancient"],
            &old_date,
        );

        std::fs::write(dir.join("new.rs"), "fn new() {}\n").unwrap();
        run_git_as(&dir, "new@example.com", &["add", "."], &[]);
        run_git_as(
            &dir,
            "new@example.com",
            &["commit", "-q", "-m", "recent"],
            &[],
        );

        let authors = active_authors_since(&dir, 30).unwrap();

        assert!(authors.contains("new@example.com"));
        assert!(!authors.contains("old@example.com"));
    }

    #[test]
    fn active_authors_since_returns_empty_set_for_repo_without_commits() {
        let dir = TempDir::new("git-active-authors-no-commits");
        git(&dir, &["init", "-q", "-b", "main"]);

        let authors = active_authors_since(&dir, DEFAULT_WINDOW_DAYS).unwrap();
        assert!(authors.is_empty());
    }

    #[test]
    fn resolve_commit_matches_git_rev_parse() {
        let dir = TempDir::new("git-resolve-commit");
        git(&dir, &["init", "-q", "-b", "main"]);
        std::fs::write(dir.join("a.rs"), "fn a() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);

        assert_eq!(
            resolve_commit(&dir, "HEAD").unwrap(),
            commit_sha(&dir, "HEAD")
        );
    }

    #[test]
    fn is_ancestor_is_true_for_a_direct_ancestor() {
        let dir = TempDir::new("git-is-ancestor-true");
        git(&dir, &["init", "-q", "-b", "main"]);
        std::fs::write(dir.join("a.rs"), "fn a() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);
        let base = commit_sha(&dir, "HEAD");

        std::fs::write(dir.join("a.rs"), "fn a() { 1 }\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "second"]);
        let head = commit_sha(&dir, "HEAD");

        assert!(is_ancestor(&dir, &base, &head).unwrap());
        assert!(!is_ancestor(&dir, &head, &base).unwrap());
    }

    #[test]
    fn is_ancestor_is_true_for_the_same_commit() {
        let dir = TempDir::new("git-is-ancestor-same");
        git(&dir, &["init", "-q", "-b", "main"]);
        std::fs::write(dir.join("a.rs"), "fn a() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);
        let head = commit_sha(&dir, "HEAD");

        assert!(is_ancestor(&dir, &head, &head).unwrap());
    }

    #[test]
    fn is_ancestor_is_false_for_a_diverged_branch() {
        let dir = TempDir::new("git-is-ancestor-diverged");
        git(&dir, &["init", "-q", "-b", "main"]);
        std::fs::write(dir.join("a.rs"), "fn a() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);
        let base = commit_sha(&dir, "HEAD");

        git(&dir, &["checkout", "-q", "-b", "feature"]);
        std::fs::write(dir.join("feature.rs"), "fn feature() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "feature work"]);
        let feature = commit_sha(&dir, "HEAD");

        git(&dir, &["checkout", "-q", "main"]);
        std::fs::write(dir.join("main.rs"), "fn main_work() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "main work"]);
        let main_tip = commit_sha(&dir, "HEAD");

        assert!(!is_ancestor(&dir, &main_tip, &feature).unwrap());
        assert!(!is_ancestor(&dir, &feature, &main_tip).unwrap());
        // Both still share `base` as a common ancestor.
        assert!(is_ancestor(&dir, &base, &main_tip).unwrap());
        assert!(is_ancestor(&dir, &base, &feature).unwrap());
    }

    #[test]
    fn git_error_source_preserves_the_underlying_error() {
        let err = GitError::Walk(Box::new(std::io::Error::other("boom")));
        let source = std::error::Error::source(&err).expect("Walk must carry a source");
        assert!(source.downcast_ref::<std::io::Error>().is_some());
        assert_eq!(err.to_string(), "failed to walk git history: boom");
        assert!(std::error::Error::source(&GitError::InvalidWindow(0)).is_none());
    }
}
