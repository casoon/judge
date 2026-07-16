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
        let commit = info.object().map_err(|err| GitError::Walk(err.to_string()))?;
        let commit_time = commit
            .time()
            .map_err(|err| GitError::Walk(err.to_string()))?
            .seconds;
        if commit_time < cutoff {
            break;
        }

        let tree = commit.tree().map_err(|err| GitError::Walk(err.to_string()))?;
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
