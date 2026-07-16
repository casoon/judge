//! Shared test fixtures: isolated temp directories for tests that need to
//! write real files (source files, `Cargo.toml` fixtures, git repositories).

#![cfg(test)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A temp directory unique to one test, removed when it goes out of scope.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(name: &str) -> Self {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("judge-test-{name}-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&path).expect("failed to create temp dir");
        Self(path)
    }
}

impl std::ops::Deref for TempDir {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
