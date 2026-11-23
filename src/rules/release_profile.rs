//! Release-profile hazards (GitHub issue #58): `release-profile-hazard` and
//! `panic-strategy-conflict`, plus the effective-profile resolution
//! `cargo judge inspect` prints.
//!
//! The effective release profile is resolved from exactly two files: the
//! workspace root `Cargo.toml` and the workspace root `.cargo/config.toml`.
//! A `[profile.*]` value in the config file overrides the manifest value for
//! the same key, as it does in Cargo. A custom profile follows its
//! `inherits` chain; only chains that end at `release` are resolved.
//!
//! Deliberately ignored, so the result is the same on every machine: the
//! user's home config (`~/.cargo/config.toml`), config files in directories
//! above the workspace root, and `CARGO_PROFILE_*` environment variables.
//! A build on a machine that sets any of those can use a different profile
//! than the one judge reports.
//!
//! Both rules only run for workspaces with at least one `bin` target: the
//! profile of a library-only workspace does not decide how a shipped binary
//! is built (a dependent crate's own profile wins).

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use syn::visit::{self, Visit};
use syn::{Item, UseTree};
use toml::Spanned;

use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::ingest::{EntryPointKind, Workspace};

/// Rule id for `opt-level = 0` or `debug-assertions = true` in the effective
/// release profile.
pub const RELEASE_PROFILE_HAZARD_RULE: &str = "release-profile-hazard";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const RELEASE_PROFILE_HAZARD_RULE_REVISION: u32 = 1;

/// Rule id for `panic = "abort"` in the effective release profile while
/// non-test code calls `std::panic::catch_unwind`.
pub const PANIC_STRATEGY_CONFLICT_RULE: &str = "panic-strategy-conflict";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const PANIC_STRATEGY_CONFLICT_RULE_REVISION: u32 = 1;

/// The profile settings `inspect` shows, in display order.
pub const SHOWN_SETTINGS: [&str; 8] = [
    "opt-level",
    "debug",
    "debug-assertions",
    "overflow-checks",
    "lto",
    "codegen-units",
    "panic",
    "strip",
];

const MANIFEST_FILE: &str = "Cargo.toml";
const CONFIG_FILE: &str = ".cargo/config.toml";

#[derive(Debug)]
pub enum ReleaseProfileError {
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, toml::de::Error),
    Source(PathBuf, syn::Error),
}

impl fmt::Display for ReleaseProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
            Self::Source(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
        }
    }
}

impl std::error::Error for ReleaseProfileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(_, err) => Some(err),
            Self::Parse(_, err) => Some(err),
            Self::Source(_, err) => Some(err),
        }
    }
}

/// Which of the two read files declared a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredIn {
    Manifest,
    Config,
}

/// Where a profile value is written: the file (relative to the workspace
/// root), its line, and the profile table that holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettingSource {
    pub declared_in: DeclaredIn,
    pub file: PathBuf,
    pub line: OneBasedLine,
    pub profile: String,
}

impl fmt::Display for SettingSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} [profile.{}]",
            self.file.display(),
            self.line.get(),
            self.profile
        )
    }
}

/// One effective setting. `source` is `None` for Cargo's built-in default.
#[derive(Debug, Clone, Serialize)]
pub struct ProfileSetting {
    pub key: String,
    pub value: toml::Value,
    pub source: Option<SettingSource>,
}

/// A `[profile.<name>.package.<spec>]` override, listed as declared and
/// never judged.
#[derive(Debug, Clone, Serialize)]
pub struct PackageOverride {
    pub package: String,
    pub settings: Vec<ProfileSetting>,
}

/// One resolved profile: `inherits` is the chain from this profile up to
/// and including `release` (just `["release"]` for the release profile).
#[derive(Debug, Clone, Serialize)]
pub struct ResolvedProfile {
    pub name: String,
    pub inherits: Vec<String>,
    pub settings: Vec<ProfileSetting>,
    pub package_overrides: Vec<PackageOverride>,
}

impl ResolvedProfile {
    pub fn setting(&self, key: &str) -> Option<&ProfileSetting> {
        self.settings.iter().find(|setting| setting.key == key)
    }
}

/// The effective release profile plus every custom profile whose
/// `inherits` chain ends at `release`, sorted by name.
#[derive(Debug, Clone, Serialize)]
pub struct ProfileReport {
    pub release: ResolvedProfile,
    pub custom: Vec<ResolvedProfile>,
}

/// Aggregated rule results across a workspace.
#[derive(Debug, Default)]
pub struct WorkspaceReleaseProfile {
    pub findings: Vec<Finding>,
    pub errors: Vec<ReleaseProfileError>,
}

/// One `[profile.<name>]` table as written, with value spans. Hand-written
/// `Deserialize` because `#[serde(flatten)]` would buffer the values and
/// lose the spans `toml::Spanned` needs.
#[derive(Default)]
struct RawProfile {
    settings: BTreeMap<String, Spanned<toml::Value>>,
    packages: BTreeMap<String, BTreeMap<String, Spanned<toml::Value>>>,
}

impl<'de> Deserialize<'de> for RawProfile {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RawProfileVisitor;

        impl<'de> Visitor<'de> for RawProfileVisitor {
            type Value = RawProfile;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a profile table")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<RawProfile, A::Error> {
                let mut raw = RawProfile::default();
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "package" => raw.packages = map.next_value()?,
                        "build-override" => {
                            map.next_value::<IgnoredAny>()?;
                        }
                        _ => {
                            let value = map.next_value()?;
                            raw.settings.insert(key, value);
                        }
                    }
                }
                Ok(raw)
            }
        }

        deserializer.deserialize_map(RawProfileVisitor)
    }
}

#[derive(Default, Deserialize)]
struct RawProfiles {
    #[serde(default)]
    profile: BTreeMap<String, RawProfile>,
}

#[derive(Default)]
struct MergedProfile {
    settings: BTreeMap<String, (toml::Value, SettingSource)>,
    packages: BTreeMap<String, BTreeMap<String, (toml::Value, SettingSource)>>,
}

fn line_of(text: &str, offset: usize) -> OneBasedLine {
    let line = text[..offset.min(text.len())].matches('\n').count() + 1;
    OneBasedLine::new(line).expect("line count starts at 1")
}

/// Reads one profile source and overlays its values onto `merged`, key by
/// key — called for the manifest first and the config file second, so a
/// config value replaces a manifest value for the same key.
fn overlay(
    merged: &mut BTreeMap<String, MergedProfile>,
    workspace_root: &Path,
    relative: &str,
    declared_in: DeclaredIn,
) -> Result<(), ReleaseProfileError> {
    let path = workspace_root.join(relative);
    if declared_in == DeclaredIn::Config && !path.is_file() {
        return Ok(());
    }
    let text =
        std::fs::read_to_string(&path).map_err(|err| ReleaseProfileError::Io(path.clone(), err))?;
    let raw: RawProfiles =
        toml::from_str(&text).map_err(|err| ReleaseProfileError::Parse(path.clone(), err))?;
    let source = |profile: &str, spanned: &Spanned<toml::Value>| SettingSource {
        declared_in,
        file: PathBuf::from(relative),
        line: line_of(&text, spanned.span().start),
        profile: profile.to_string(),
    };
    for (name, profile) in raw.profile {
        let target = merged.entry(name.clone()).or_default();
        for (key, spanned) in &profile.settings {
            target.settings.insert(
                key.clone(),
                (spanned.get_ref().clone(), source(&name, spanned)),
            );
        }
        for (package, settings) in &profile.packages {
            let package_target = target.packages.entry(package.clone()).or_default();
            for (key, spanned) in settings {
                package_target.insert(
                    key.clone(),
                    (spanned.get_ref().clone(), source(&name, spanned)),
                );
            }
        }
    }
    Ok(())
}

/// The chain from `name` to `release` following `inherits` (`bench`
/// inherits `release` implicitly), or `None` when it ends elsewhere, is
/// missing a link, or loops.
fn chain_to_release(merged: &BTreeMap<String, MergedProfile>, name: &str) -> Option<Vec<String>> {
    let mut chain: Vec<String> = Vec::new();
    let mut current = name.to_string();
    loop {
        if chain.contains(&current) {
            return None;
        }
        chain.push(current.clone());
        let next = match current.as_str() {
            "release" => return Some(chain),
            "bench" => "release".to_string(),
            "dev" | "test" => return None,
            _ => merged
                .get(&current)
                .and_then(|profile| profile.settings.get("inherits"))
                .and_then(|(value, _)| value.as_str())?
                .to_string(),
        };
        current = next;
    }
}

/// Whether a `debug` value enables any debuginfo.
fn debug_enabled(value: &toml::Value) -> bool {
    match value {
        toml::Value::Boolean(enabled) => *enabled,
        toml::Value::Integer(level) => *level != 0,
        toml::Value::String(level) => level != "none" && level != "0",
        _ => true,
    }
}

/// Cargo's built-in release default for `key`. `strip` defaults to
/// `"debuginfo"` when the effective profile enables no debuginfo (Cargo
/// 1.77+), otherwise `"none"`.
fn release_default(key: &str, debug: &toml::Value) -> toml::Value {
    match key {
        "opt-level" => toml::Value::Integer(3),
        "codegen-units" => toml::Value::Integer(16),
        "panic" => toml::Value::String("unwind".to_string()),
        "strip" if debug_enabled(debug) => toml::Value::String("none".to_string()),
        "strip" => toml::Value::String("debuginfo".to_string()),
        _ => toml::Value::Boolean(false),
    }
}

fn resolve_profile(
    merged: &BTreeMap<String, MergedProfile>,
    chain: Vec<String>,
) -> ResolvedProfile {
    let declared = |key: &str| {
        chain.iter().find_map(|name| {
            merged
                .get(name)
                .and_then(|profile| profile.settings.get(key))
                .cloned()
        })
    };
    let debug = declared("debug")
        .map(|(value, _)| value)
        .unwrap_or(toml::Value::Boolean(false));
    let settings = SHOWN_SETTINGS
        .iter()
        .map(|key| match declared(key) {
            Some((value, source)) => ProfileSetting {
                key: key.to_string(),
                value,
                source: Some(source),
            },
            None => ProfileSetting {
                key: key.to_string(),
                value: release_default(key, &debug),
                source: None,
            },
        })
        .collect();
    let package_overrides = merged
        .get(&chain[0])
        .map(|profile| {
            profile
                .packages
                .iter()
                .map(|(package, settings)| PackageOverride {
                    package: package.clone(),
                    settings: settings
                        .iter()
                        .map(|(key, (value, source))| ProfileSetting {
                            key: key.clone(),
                            value: value.clone(),
                            source: Some(source.clone()),
                        })
                        .collect(),
                })
                .collect()
        })
        .unwrap_or_default();
    ResolvedProfile {
        name: chain[0].clone(),
        inherits: chain[1..].to_vec(),
        settings,
        package_overrides,
    }
}

/// Resolves the effective release profile and every custom profile that
/// inherits from it (see module docs for which files are read).
pub fn resolve(workspace_root: &Path) -> Result<ProfileReport, ReleaseProfileError> {
    let mut merged: BTreeMap<String, MergedProfile> = BTreeMap::new();
    overlay(
        &mut merged,
        workspace_root,
        MANIFEST_FILE,
        DeclaredIn::Manifest,
    )?;
    overlay(&mut merged, workspace_root, CONFIG_FILE, DeclaredIn::Config)?;

    let release = resolve_profile(&merged, vec!["release".to_string()]);
    let custom = merged
        .keys()
        .filter(|name| !matches!(name.as_str(), "release" | "dev" | "test" | "bench"))
        .filter_map(|name| chain_to_release(&merged, name))
        .map(|chain| resolve_profile(&merged, chain))
        .collect();
    Ok(ProfileReport { release, custom })
}

/// Whether any workspace crate has a `bin` target — the precondition for
/// both rules and for `inspect`'s release-profile section.
pub fn workspace_builds_binaries(workspace: &Workspace) -> bool {
    workspace.crates.iter().any(|krate| {
        krate
            .entry_points
            .iter()
            .any(|entry| entry.kind == EntryPointKind::Bin)
    })
}

fn value_json(value: &toml::Value) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or(serde_json::Value::Null)
}

fn setting_finding(
    rule: &str,
    workspace_root: &Path,
    setting: &ProfileSetting,
    source: &SettingSource,
    evidence: serde_json::Value,
) -> Finding {
    Finding::new(
        format!("{rule}:{}", setting.key),
        rule,
        Severity::Warn,
        Location {
            file: workspace_root.join(&source.file),
            line: source.line,
            item_path: format!("profile.release.{}", setting.key),
        },
        EvidenceClass::DerivedFact,
        Origin::Code,
        Some(evidence),
    )
}

/// `release-profile-hazard`: `opt-level = 0` or `debug-assertions = true`
/// written in the effective release profile. Built-in defaults never
/// trigger it.
fn release_profile_hazards(workspace_root: &Path, release: &ResolvedProfile) -> Vec<Finding> {
    release
        .settings
        .iter()
        .filter_map(|setting| {
            let source = setting.source.as_ref()?;
            let hazard = match (setting.key.as_str(), &setting.value) {
                ("opt-level", toml::Value::Integer(0)) => true,
                ("opt-level", toml::Value::String(level)) => level == "0",
                ("debug-assertions", toml::Value::Boolean(enabled)) => *enabled,
                _ => false,
            };
            hazard.then(|| {
                setting_finding(
                    RELEASE_PROFILE_HAZARD_RULE,
                    workspace_root,
                    setting,
                    source,
                    serde_json::json!({
                        "profile": "release",
                        "setting": setting.key,
                        "value": value_json(&setting.value),
                        "declared_in": source.declared_in,
                        "file": source.file,
                    }),
                )
            })
        })
        .collect()
}

/// One `std::panic::catch_unwind` reference in non-test code.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CatchUnwindSite {
    file: PathBuf,
    line: usize,
    column: usize,
    form: &'static str,
}

fn item_attrs(item: &Item) -> &[syn::Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

fn is_test_scoped(attrs: &[syn::Attribute]) -> bool {
    crate::functions::attrs_have_cfg_test(attrs) || crate::functions::has_test_attr(attrs)
}

/// Collects `std::panic::catch_unwind` / `panic::catch_unwind` paths and
/// `use std::panic::catch_unwind` imports, skipping `#[cfg(test)]` and
/// `#[test]` items.
#[derive(Default)]
struct CatchUnwindVisitor {
    sites: Vec<(usize, usize, &'static str)>,
}

impl CatchUnwindVisitor {
    fn record(&mut self, span: proc_macro2::Span, form: &'static str) {
        let start = span.start();
        self.sites.push((start.line, start.column + 1, form));
    }

    fn collect_use(&mut self, tree: &UseTree, prefix: &mut Vec<String>) {
        let (ident, last) = match tree {
            UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                self.collect_use(&path.tree, prefix);
                prefix.pop();
                return;
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.collect_use(item, prefix);
                }
                return;
            }
            UseTree::Name(name) => (&name.ident, name.ident.to_string()),
            UseTree::Rename(rename) => (&rename.ident, rename.ident.to_string()),
            UseTree::Glob(_) => return,
        };
        if prefix.len() == 2 && prefix[0] == "std" && prefix[1] == "panic" && last == "catch_unwind"
        {
            self.record(ident.span(), "import");
        }
    }
}

impl<'ast> Visit<'ast> for CatchUnwindVisitor {
    fn visit_item(&mut self, item: &'ast Item) {
        if is_test_scoped(item_attrs(item)) {
            return;
        }
        if let Item::Use(item_use) = item {
            self.collect_use(&item_use.tree, &mut Vec::new());
            return;
        }
        visit::visit_item(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if !is_test_scoped(&item.attrs) {
            visit::visit_impl_item_fn(self, item);
        }
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if !is_test_scoped(&item.attrs) {
            visit::visit_trait_item_fn(self, item);
        }
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segments: Vec<String> = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        let is_catch_unwind = matches!(
            segments
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
            ["std", "panic", "catch_unwind"] | ["panic", "catch_unwind"]
        );
        if is_catch_unwind {
            let last = path.segments.last().expect("matched a non-empty path");
            self.record(last.ident.span(), "path");
        }
        visit::visit_path(self, path);
    }
}

/// Every `catch_unwind` site in the workspace's non-test code: files in a
/// crate's normal source domain (not `tests/`, `examples/`, `benches/`,
/// `build.rs` — those ignore the release `panic` setting or never ship),
/// minus files reachable only through `#[cfg(test)] mod`.
fn catch_unwind_sites(
    workspace: &Workspace,
    errors: &mut Vec<ReleaseProfileError>,
) -> Vec<CatchUnwindSite> {
    let mut sites = Vec::new();
    for krate in &workspace.crates {
        let paths: Vec<PathBuf> = krate
            .source_files
            .iter()
            .map(|file| file.path.clone())
            .collect();
        let test_only = crate::rules::module_graph::cfg_test_module_files(&paths);
        for path in paths {
            let relative = path.strip_prefix(&krate.root).unwrap_or(&path);
            if crate::rules::deps::classify_domain(relative)
                != crate::rules::deps::UsageDomain::Normal
                || test_only.contains(&path)
            {
                continue;
            }
            let parsed = match crate::functions::read_and_parse_source(
                &path,
                |err| ReleaseProfileError::Io(path.clone(), err),
                |err| ReleaseProfileError::Source(path.clone(), err),
            ) {
                Ok(parsed) => parsed,
                Err(err) => {
                    errors.push(err);
                    continue;
                }
            };
            let mut visitor = CatchUnwindVisitor::default();
            visitor.visit_file(&parsed.ast);
            let display = path
                .strip_prefix(&workspace.root)
                .unwrap_or(&path)
                .to_path_buf();
            sites.extend(
                visitor
                    .sites
                    .into_iter()
                    .map(|(line, column, form)| CatchUnwindSite {
                        file: display.clone(),
                        line,
                        column,
                        form,
                    }),
            );
        }
    }
    sites.sort();
    sites
}

/// `panic-strategy-conflict`: the effective release profile declares
/// `panic = "abort"` and non-test code references
/// `std::panic::catch_unwind`. One finding at the `panic` line; the code
/// sites are listed in its evidence.
fn panic_strategy_conflict(
    workspace: &Workspace,
    release: &ResolvedProfile,
    errors: &mut Vec<ReleaseProfileError>,
) -> Option<Finding> {
    let setting = release.setting("panic")?;
    let source = setting.source.as_ref()?;
    if setting.value.as_str() != Some("abort") {
        return None;
    }
    let sites = catch_unwind_sites(workspace, errors);
    if sites.is_empty() {
        return None;
    }
    let sites_json: Vec<serde_json::Value> = sites
        .iter()
        .map(|site| {
            serde_json::json!({
                "file": site.file,
                "line": site.line,
                "column": site.column,
                "form": site.form,
            })
        })
        .collect();
    Some(setting_finding(
        PANIC_STRATEGY_CONFLICT_RULE,
        &workspace.root,
        setting,
        source,
        serde_json::json!({
            "profile": "release",
            "setting": "panic",
            "value": "abort",
            "declared_in": source.declared_in,
            "file": source.file,
            "catch_unwind_sites": sites_json,
        }),
    ))
}

/// Runs both rules. Nothing runs for a workspace without a `bin` target.
pub fn analyze_workspace(workspace: &Workspace) -> WorkspaceReleaseProfile {
    let mut report = WorkspaceReleaseProfile::default();
    if !workspace_builds_binaries(workspace) {
        return report;
    }
    let profiles = match resolve(&workspace.root) {
        Ok(profiles) => profiles,
        Err(err) => {
            report.errors.push(err);
            return report;
        }
    };
    report.findings = release_profile_hazards(&workspace.root, &profiles.release);
    report.findings.extend(panic_strategy_conflict(
        workspace,
        &profiles.release,
        &mut report.errors,
    ));
    report
}

/// A profile value as `inspect` prints it: strings bare, everything else in
/// TOML notation.
pub fn display_value(value: &toml::Value) -> String {
    match value {
        toml::Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    const BIN_PACKAGE: &str =
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";

    /// A single-package workspace with a `src/main.rs` bin target; `extra`
    /// is appended to the manifest verbatim.
    fn write_bin_fixture(dir: &TempDir, extra: &str, main_rs: &str) {
        std::fs::write(dir.join("Cargo.toml"), format!("{BIN_PACKAGE}{extra}")).unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/main.rs"), main_rs).unwrap();
    }

    fn write_config(dir: &TempDir, text: &str) {
        std::fs::create_dir_all(dir.join(".cargo")).unwrap();
        std::fs::write(dir.join(".cargo/config.toml"), text).unwrap();
    }

    fn analyze(dir: &TempDir) -> WorkspaceReleaseProfile {
        let workspace = crate::ingest::load(Some(&dir.join("Cargo.toml"))).unwrap();
        let report = analyze_workspace(&workspace);
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        report
    }

    fn rule_hits<'a>(report: &'a WorkspaceReleaseProfile, rule: &str) -> Vec<&'a Finding> {
        report.findings.iter().filter(|f| f.rule == rule).collect()
    }

    const MAIN: &str = "fn main() {}\n";

    #[test]
    fn opt_level_zero_in_the_manifest_is_flagged_at_its_line() {
        let dir = TempDir::new("release-profile-opt-level-zero");
        write_bin_fixture(&dir, "\n[profile.release]\nopt-level = 0\n", MAIN);
        let report = analyze(&dir);
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.rule, RELEASE_PROFILE_HAZARD_RULE);
        assert_eq!(finding.location.file, dir.join("Cargo.toml"));
        assert_eq!(finding.location.line, 7);
        assert_eq!(finding.location.item_path, "profile.release.opt-level");
    }

    #[test]
    fn debug_assertions_true_in_the_config_is_flagged_at_the_config_line() {
        let dir = TempDir::new("release-profile-debug-assertions-config");
        write_bin_fixture(
            &dir,
            "\n[profile.release]\ndebug-assertions = false\n",
            MAIN,
        );
        write_config(&dir, "[profile.release]\ndebug-assertions = true\n");
        let report = analyze(&dir);
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.rule, RELEASE_PROFILE_HAZARD_RULE);
        assert_eq!(finding.location.file, dir.join(".cargo/config.toml"));
        assert_eq!(finding.location.line, 2);
        assert_eq!(finding.evidence.as_ref().unwrap()["declared_in"], "config");
    }

    #[test]
    fn a_config_value_overrides_the_manifest_in_resolution_and_findings() {
        let dir = TempDir::new("release-profile-config-overrides");
        write_bin_fixture(&dir, "\n[profile.release]\nopt-level = 0\n", MAIN);
        write_config(&dir, "[profile.release]\nopt-level = 3\n");

        let profiles = resolve(&dir).unwrap();
        let opt_level = profiles.release.setting("opt-level").unwrap();
        assert_eq!(opt_level.value, toml::Value::Integer(3));
        let source = opt_level.source.as_ref().unwrap();
        assert_eq!(source.declared_in, DeclaredIn::Config);
        assert_eq!(source.file, PathBuf::from(".cargo/config.toml"));
        assert_eq!(source.line, 2);

        assert!(analyze(&dir).findings.is_empty());
    }

    #[test]
    fn the_default_release_profile_produces_no_findings() {
        let dir = TempDir::new("release-profile-default");
        write_bin_fixture(
            &dir,
            "",
            "fn main() {\n    let _ = std::panic::catch_unwind(|| ());\n}\n",
        );
        assert!(analyze(&dir).findings.is_empty());

        let profiles = resolve(&dir).unwrap();
        assert!(profiles.release.settings.iter().all(|s| s.source.is_none()));
        assert_eq!(
            profiles.release.setting("opt-level").unwrap().value,
            toml::Value::Integer(3)
        );
        assert_eq!(
            profiles.release.setting("panic").unwrap().value.as_str(),
            Some("unwind")
        );
        assert!(profiles.custom.is_empty());
    }

    #[test]
    fn a_library_only_workspace_is_not_judged() {
        let dir = TempDir::new("release-profile-lib-only");
        std::fs::write(
            dir.join("Cargo.toml"),
            format!("{BIN_PACKAGE}\n[profile.release]\nopt-level = 0\n"),
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        assert!(analyze(&dir).findings.is_empty());
    }

    #[test]
    fn a_custom_profile_inheriting_release_is_resolved_through_its_chain() {
        let dir = TempDir::new("release-profile-custom-inherits");
        write_bin_fixture(
            &dir,
            "\n[profile.release]\nlto = true\npanic = \"abort\"\n\n[profile.dist]\ninherits = \"release\"\ncodegen-units = 1\n\n[profile.dist-debug]\ninherits = \"dist\"\ndebug = true\n\n[profile.local]\ninherits = \"dev\"\n",
            MAIN,
        );
        write_config(&dir, "[profile.dist]\nstrip = \"symbols\"\n");
        let profiles = resolve(&dir).unwrap();
        let names: Vec<&str> = profiles.custom.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["dist", "dist-debug"]);

        let dist = &profiles.custom[0];
        assert_eq!(dist.inherits, ["release"]);
        assert_eq!(
            dist.setting("lto").unwrap().value,
            toml::Value::Boolean(true)
        );
        assert_eq!(
            dist.setting("lto")
                .unwrap()
                .source
                .as_ref()
                .unwrap()
                .profile,
            "release"
        );
        assert_eq!(
            dist.setting("codegen-units").unwrap().value,
            toml::Value::Integer(1)
        );
        assert_eq!(
            dist.setting("strip").unwrap().value.as_str(),
            Some("symbols")
        );
        assert_eq!(
            dist.setting("strip")
                .unwrap()
                .source
                .as_ref()
                .unwrap()
                .declared_in,
            DeclaredIn::Config
        );
        assert_eq!(dist.setting("opt-level").unwrap().source, None);

        let dist_debug = &profiles.custom[1];
        assert_eq!(dist_debug.inherits, ["dist", "release"]);
        assert_eq!(
            dist_debug.setting("codegen-units").unwrap().value,
            toml::Value::Integer(1)
        );
        assert_eq!(
            dist_debug.setting("strip").unwrap().value.as_str(),
            Some("symbols")
        );
        assert_eq!(
            dist_debug.setting("debug").unwrap().value,
            toml::Value::Boolean(true)
        );
    }

    #[test]
    fn package_overrides_are_listed_but_not_judged() {
        let dir = TempDir::new("release-profile-package-override");
        write_bin_fixture(
            &dir,
            "\n[profile.release.package.app]\nopt-level = 0\n",
            MAIN,
        );
        let profiles = resolve(&dir).unwrap();
        assert_eq!(profiles.release.package_overrides.len(), 1);
        let package_override = &profiles.release.package_overrides[0];
        assert_eq!(package_override.package, "app");
        assert_eq!(package_override.settings[0].key, "opt-level");
        assert_eq!(
            package_override.settings[0].source.as_ref().unwrap().line,
            7
        );
        assert!(analyze(&dir).findings.is_empty());
    }

    #[test]
    fn panic_abort_with_catch_unwind_in_production_code_is_flagged_at_the_panic_line() {
        let dir = TempDir::new("release-profile-panic-conflict");
        write_bin_fixture(
            &dir,
            "\n[profile.release]\npanic = \"abort\"\n",
            "use std::panic::catch_unwind;\n\nfn main() {\n    let _ = catch_unwind(|| ());\n}\n",
        );
        let report = analyze(&dir);
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.rule, PANIC_STRATEGY_CONFLICT_RULE);
        assert_eq!(finding.location.file, dir.join("Cargo.toml"));
        assert_eq!(finding.location.line, 7);
        let sites = finding.evidence.as_ref().unwrap()["catch_unwind_sites"]
            .as_array()
            .unwrap();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0]["file"], "src/main.rs");
        assert_eq!(sites[0]["line"], 1);
        assert_eq!(sites[0]["form"], "import");
    }

    #[test]
    fn catch_unwind_only_in_cfg_test_code_is_not_a_panic_strategy_conflict() {
        let dir = TempDir::new("release-profile-panic-cfg-test");
        write_bin_fixture(
            &dir,
            "\n[profile.release]\npanic = \"abort\"\n",
            "fn main() {}\n\n#[cfg(test)]\nmod tests {\n    use std::panic::catch_unwind;\n\n    #[test]\n    fn recovers() {\n        assert!(catch_unwind(|| panic!()).is_err());\n        let _ = std::panic::catch_unwind(|| ());\n    }\n}\n\n#[test]\nfn top_level() {\n    let _ = std::panic::catch_unwind(|| ());\n}\n",
        );
        assert!(analyze(&dir).findings.is_empty());
    }

    #[test]
    fn panic_unwind_with_catch_unwind_is_not_flagged() {
        let dir = TempDir::new("release-profile-panic-unwind");
        write_bin_fixture(
            &dir,
            "\n[profile.release]\npanic = \"unwind\"\n",
            "fn main() {\n    let _ = std::panic::catch_unwind(|| ());\n}\n",
        );
        assert!(analyze(&dir).findings.is_empty());
    }

    #[test]
    fn catch_unwind_paths_and_imports_are_both_recognized() {
        let file = syn::parse_file(
            "use std::panic::{self, catch_unwind as cu};\nuse std::panic::AssertUnwindSafe;\nfn f() {\n    let _ = panic::catch_unwind(|| ());\n    let _ = ::std::panic::catch_unwind(|| ());\n    let _ = cu(|| ());\n}\n",
        )
        .unwrap();
        let mut visitor = CatchUnwindVisitor::default();
        visitor.visit_file(&file);
        let forms: Vec<(usize, &str)> = visitor
            .sites
            .iter()
            .map(|(line, _, form)| (*line, *form))
            .collect();
        assert_eq!(forms, [(1, "import"), (4, "path"), (5, "path")]);
    }

    /// The registry's curated `example.before` for this rule (see
    /// `rule_registry::RULE_REGISTRY`) must itself still trigger the rule —
    /// this is what keeps a landing-page-facing example from silently
    /// drifting away from what judge actually flags.
    #[test]
    fn release_profile_hazard_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(RELEASE_PROFILE_HAZARD_RULE)
            .expect("release-profile-hazard has a registry entry")
            .example
            .expect("release-profile-hazard has a curated example")
            .before;
        let dir = TempDir::new("release-profile-hazard-registry-example");
        write_bin_fixture(&dir, &format!("\n{example}"), MAIN);
        let report = analyze(&dir);
        assert_eq!(rule_hits(&report, RELEASE_PROFILE_HAZARD_RULE).len(), 1);
    }

    /// Same drift guard for `panic-strategy-conflict`: the example holds a
    /// `# Cargo.toml` part and a `// src/main.rs` part.
    #[test]
    fn panic_strategy_conflict_registry_example_still_triggers_the_rule() {
        let example = crate::rule_registry::lookup(PANIC_STRATEGY_CONFLICT_RULE)
            .expect("panic-strategy-conflict has a registry entry")
            .example
            .expect("panic-strategy-conflict has a curated example")
            .before;
        let (manifest, main_rs) = example
            .split_once("// src/main.rs\n")
            .expect("example has a src/main.rs part");
        let dir = TempDir::new("panic-strategy-conflict-registry-example");
        write_bin_fixture(&dir, &format!("\n{manifest}"), main_rs);
        let report = analyze(&dir);
        assert_eq!(rule_hits(&report, PANIC_STRATEGY_CONFLICT_RULE).len(), 1);
    }

    #[test]
    fn release_profile_error_source_preserves_the_underlying_error() {
        let err =
            ReleaseProfileError::Io(PathBuf::from("Cargo.toml"), std::io::Error::other("boom"));
        let source = std::error::Error::source(&err).expect("Io must carry a source");
        assert!(source.downcast_ref::<std::io::Error>().is_some());
        assert_eq!(err.to_string(), "Cargo.toml: failed to read file: boom");
    }
}
