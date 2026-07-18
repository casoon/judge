//! Git signals: file churn, computed via `gix` — no `git` subprocess (see
//! todo.md §2, §3.E).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use gix::bstr::ByteSlice;

use crate::complexity::FunctionInfo;
use crate::finding::{EvidenceClass, Finding, Location, Origin, Severity};

/// Default lookback window for churn: 12 months.
pub const DEFAULT_WINDOW_DAYS: i64 = 365;

/// Rule id used for [`Hotspot`] findings (see todo.md §3.E).
pub const HOTSPOT_RULE: &str = "hotspot";
/// Bump when the hotspot rule's logic changes, so a baseline taken under an
/// older revision doesn't silently protect findings from a real rule change
/// (see todo.md §5 "Regelversions-Schutz").
pub const HOTSPOT_RULE_REVISION: u32 = 1;

#[derive(Debug)]
pub enum GitError {
    Open(Box<gix::open::Error>),
    Walk(String),
    RevParse(String, String),
    Status(String),
    InvalidWindow(i64),
}

impl std::fmt::Display for GitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(err) => write!(f, "failed to open git repository: {err}"),
            Self::Walk(msg) => write!(f, "failed to walk git history: {msg}"),
            Self::RevParse(spec, msg) => write!(f, "failed to resolve `{spec}`: {msg}"),
            Self::Status(msg) => write!(f, "failed to read repository status: {msg}"),
            Self::InvalidWindow(days) => {
                write!(f, "invalid lookback window: {days} days (must be positive)")
            }
        }
    }
}

impl std::error::Error for GitError {}

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
        .map_err(|err| GitError::Walk(err.to_string()))?;

    for info in walk {
        let info = info.map_err(|err| GitError::Walk(err.to_string()))?;
        let commit = info
            .object()
            .map_err(|err| GitError::Walk(err.to_string()))?;

        let tree = commit
            .tree()
            .map_err(|err| GitError::Walk(err.to_string()))?;
        let parent_tree = match commit.parent_ids().next() {
            Some(parent_id) => parent_id
                .object()
                .map_err(|err| GitError::Walk(err.to_string()))?
                .into_commit()
                .tree()
                .map_err(|err| GitError::Walk(err.to_string()))?,
            None => repo.empty_tree(),
        };

        parent_tree
            .changes()
            .map_err(|err| GitError::Walk(err.to_string()))?
            .for_each_to_obtain_tree(&tree, |change| {
                if let Some(path) = path_of(&change) {
                    *counts.entry(path).or_insert(0u32) += 1;
                }
                Ok::<_, std::convert::Infallible>(gix::object::tree::diff::Action::Continue(()))
            })
            .map_err(|err| GitError::Walk(err.to_string()))?;
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
        .map_err(|err| GitError::Walk(err.to_string()))?;

    for info in walk {
        let info = info.map_err(|err| GitError::Walk(err.to_string()))?;
        let commit = info
            .object()
            .map_err(|err| GitError::Walk(err.to_string()))?;
        let commit_time = commit
            .time()
            .map_err(|err| GitError::Walk(err.to_string()))?
            .seconds;

        let tree = commit
            .tree()
            .map_err(|err| GitError::Walk(err.to_string()))?;
        let parent_tree = match commit.parent_ids().next() {
            Some(parent_id) => parent_id
                .object()
                .map_err(|err| GitError::Walk(err.to_string()))?
                .into_commit()
                .tree()
                .map_err(|err| GitError::Walk(err.to_string()))?,
            None => repo.empty_tree(),
        };

        let mut files_changed = Vec::new();
        parent_tree
            .changes()
            .map_err(|err| GitError::Walk(err.to_string()))?
            .for_each_to_obtain_tree(&tree, |change| {
                if let Some(path) = path_of(&change) {
                    files_changed.push(path);
                }
                Ok::<_, std::convert::Infallible>(gix::object::tree::diff::Action::Continue(()))
            })
            .map_err(|err| GitError::Walk(err.to_string()))?;

        let author = commit
            .author()
            .map_err(|err| GitError::Walk(err.to_string()))?;
        let author_email = author.email.to_str_lossy().trim().to_string();

        let decoded = commit
            .decode()
            .map_err(|err| GitError::Walk(err.to_string()))?;
        let trailers = decoded
            .attribution_trailers()
            .map(|trailer| {
                (
                    trailer.token.to_str_lossy().into_owned(),
                    trailer.value.to_str_lossy().into_owned(),
                )
            })
            .collect();

        let message = commit
            .message()
            .map_err(|err| GitError::Walk(err.to_string()))?;
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
            id: format!("{HOTSPOT_RULE}:{}", self.file.display()),
            rule: HOTSPOT_RULE.to_string(),
            severity: Severity::Info,
            location: Location {
                file: self.file.clone(),
                line: 1,
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

/// The current `HEAD` commit as a full hex object id (see todo.md §5,
/// `first_seen_commit`).
pub fn head_commit(repo_root: &Path) -> Result<String, GitError> {
    let repo = gix::open(repo_root)?;
    let head_id = repo
        .head_id()
        .map_err(|err| GitError::Walk(err.to_string()))?;
    Ok(head_id.to_string())
}

/// Resolves `spec` (a commit-ish — branch, tag, or short/long sha) to its
/// full hex object id (see `audit --since`, todo.md §5).
pub fn resolve_commit(repo_root: &Path, spec: &str) -> Result<String, GitError> {
    let repo = gix::open(repo_root)?;
    let id = repo
        .rev_parse_single(spec)
        .map_err(|err| GitError::RevParse(spec.to_string(), err.to_string()))?;
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
        .map_err(|err| GitError::RevParse(ancestor.to_string(), err.to_string()))?
        .detach();
    let descendant_id = repo
        .rev_parse_single(descendant)
        .map_err(|err| GitError::RevParse(descendant.to_string(), err.to_string()))?
        .detach();

    if ancestor_id == descendant_id {
        return Ok(true);
    }

    match repo.merge_base(ancestor_id, descendant_id) {
        Ok(base) => Ok(base.detach() == ancestor_id),
        Err(gix::repository::merge_base::Error::NotFound { .. }) => Ok(false),
        Err(err) => Err(GitError::Walk(err.to_string())),
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
        .map_err(|err| GitError::RevParse(since_commit.to_string(), err.to_string()))?;
    let head_id = repo
        .head_id()
        .map_err(|err| GitError::Walk(err.to_string()))?;

    let since_tree = since_id
        .object()
        .map_err(|err| GitError::Walk(err.to_string()))?
        .into_commit()
        .tree()
        .map_err(|err| GitError::Walk(err.to_string()))?;
    let head_tree = head_id
        .object()
        .map_err(|err| GitError::Walk(err.to_string()))?
        .into_commit()
        .tree()
        .map_err(|err| GitError::Walk(err.to_string()))?;

    let mut changed = std::collections::HashSet::new();
    since_tree
        .changes()
        .map_err(|err| GitError::Walk(err.to_string()))?
        .for_each_to_obtain_tree(&head_tree, |change| {
            if let Some(path) = path_of(&change) {
                changed.insert(path);
            }
            Ok::<_, std::convert::Infallible>(gix::object::tree::diff::Action::Continue(()))
        })
        .map_err(|err| GitError::Walk(err.to_string()))?;

    let status = repo
        .status(gix::progress::Discard)
        .map_err(|err| GitError::Status(err.to_string()))?
        .untracked_files(gix::status::UntrackedFiles::Files);
    let status_items = status
        .into_iter(Vec::<gix::bstr::BString>::new())
        .map_err(|err| GitError::Status(err.to_string()))?;
    for item in status_items {
        let item = item.map_err(|err| GitError::Status(err.to_string()))?;
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
        .map_err(|err| GitError::Walk(err.to_string()))?;

    for info in walk {
        let info = info.map_err(|err| GitError::Walk(err.to_string()))?;
        let commit = info
            .object()
            .map_err(|err| GitError::Walk(err.to_string()))?;

        let author = commit
            .author()
            .map_err(|err| GitError::Walk(err.to_string()))?;
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
}
