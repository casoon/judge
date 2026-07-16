//! Git signals: file churn, computed via `gix` — no `git` subprocess (see
//! todo.md §2, §3.E).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use gix::bstr::ByteSlice;

/// Default lookback window for churn: 12 months.
pub const DEFAULT_WINDOW_DAYS: i64 = 365;

#[derive(Debug)]
pub enum GitError {
    Open(Box<gix::open::Error>),
    Walk(String),
}

impl std::fmt::Display for GitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(err) => write!(f, "failed to open git repository: {err}"),
            Self::Walk(msg) => write!(f, "failed to walk git history: {msg}"),
        }
    }
}

impl std::error::Error for GitError {}

impl From<gix::open::Error> for GitError {
    fn from(err: gix::open::Error) -> Self {
        Self::Open(Box::new(err))
    }
}

/// Number of commits touching each file within `window_days` of now, keyed
/// by path relative to the repository root. Commits are walked from HEAD;
/// an unborn HEAD (no commits yet) yields an empty map rather than an error.
pub fn churn(repo_root: &Path, window_days: i64) -> Result<HashMap<PathBuf, u32>, GitError> {
    let repo = gix::open(repo_root)?;
    let mut counts = HashMap::new();

    let Ok(head_id) = repo.head_id() else {
        return Ok(counts);
    };

    let cutoff = now_unix_seconds() - window_days * 24 * 3600;

    let walk = repo
        .rev_walk(Some(head_id.detach()))
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
        if commit_time < cutoff {
            break;
        }

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

fn path_of(change: &gix::object::tree::diff::Change<'_, '_, '_>) -> Option<PathBuf> {
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
}
