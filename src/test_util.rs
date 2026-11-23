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

/// The `#[serde(default = "…")]` blind spot (issue #56): `settings` defines
/// `pub fn default_port`, and `app` names it only inside a serde derive
/// attribute — a reference that exists only in the derive's expansion. The
/// lockfile is resolved offline from the local cargo registry cache.
#[cfg(feature = "deep")]
pub fn write_serde_default_fixture(dir: &Path) {
    std::fs::write(
        dir.join("Cargo.toml"),
        "[workspace]\nmembers = [\"settings\", \"app\"]\nresolver = \"2\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.join("settings/src")).unwrap();
    std::fs::write(
        dir.join("settings/Cargo.toml"),
        "[package]\nname = \"settings\"\nversion = \"0.1.0\"\nedition = \"2021\"\npublish = false\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("settings/src/lib.rs"),
        "pub fn default_port() -> u16 {\n    8080\n}\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.join("app/src")).unwrap();
    std::fs::write(
        dir.join("app/Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\npublish = false\n\n\
         [dependencies]\nsettings = { path = \"../settings\" }\n\
         serde = { version = \"1\", features = [\"derive\"] }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("app/src/lib.rs"),
        "use serde::Deserialize;\n\n#[derive(Deserialize)]\npub struct Config {\n    \
         #[serde(default = \"settings::default_port\")]\n    pub port: u16,\n}\n",
    )
    .unwrap();
    let status = std::process::Command::new("cargo")
        .args(["generate-lockfile", "--offline", "--quiet"])
        .current_dir(dir)
        .status()
        .expect("cargo must be runnable");
    assert!(
        status.success(),
        "resolving serde offline needs serde 1.x in the local cargo registry cache"
    );
}

/// A package whose `build.rs` writes `generated_caller` into `OUT_DIR`; the
/// lib pulls it in with `include!`, and `src/main.rs` calls it. The only
/// caller of `pub fn workspace_helper` is that generated function.
#[cfg(feature = "deep")]
pub fn write_build_rs_caller_fixture(dir: &Path) {
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"genfix\"\nversion = \"0.1.0\"\nedition = \"2021\"\npublish = false\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("build.rs"),
        r#"fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(
        std::path::Path::new(&out_dir).join("generated.rs"),
        "pub fn generated_caller() -> i32 {\n    crate::workspace_helper()\n}\n",
    )
    .unwrap();
}
"#,
    )
    .unwrap();
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(
        dir.join("src/lib.rs"),
        "pub fn workspace_helper() -> i32 {\n    1\n}\n\n\
         include!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("src/main.rs"),
        "fn main() {\n    genfix::generated_caller();\n}\n",
    )
    .unwrap();
}

/// A package whose `build.rs` always fails.
#[cfg(feature = "deep")]
pub fn write_failing_build_rs_fixture(dir: &Path) {
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"failing-build\"\nversion = \"0.1.0\"\nedition = \"2021\"\npublish = false\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("build.rs"),
        "fn main() {\n    panic!(\"fixture build script fails on purpose\");\n}\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("src/lib.rs"), "pub fn item() -> i32 {\n    1\n}\n").unwrap();
}
