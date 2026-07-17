//! G5 "Slopsquatting" detectors (see todo.md §14.2 G5): declared
//! dependencies checked for signs of AI-hallucinated or typosquatted crate
//! names.
//!
//! Four rules live here:
//!
//! - `name-collision-risk` — fully local, offline, deterministic: a declared
//!   dependency name is Levenshtein-close to a well-known crate from a
//!   bundled static list ([`POPULAR_CRATES_RAW`]).
//! - `phantom-crate` — the declared crate does not exist on crates.io at
//!   all, checked via the sparse index.
//! - `phantom-version` — the crate exists, but no published, non-yanked
//!   version satisfies the declared requirement.
//! - `fresh-low-reputation-dep` — the crate exists, but is young, has few
//!   downloads, and has no repository link (crates.io REST API).
//!
//! The last three need real network access (crates.io), which judge only
//! ever performs when explicitly requested — see `--check-crates-io` on
//! `cargo judge deps` in `src/main.rs`. Bare `cargo judge`/`audit` never
//! call out to the network; only `name-collision-risk` runs there.
//!
//! `dep-added-by-agent` (the fifth rule from todo.md's G5 table) is
//! deliberately not implemented — see the "Bewusst noch nicht umgesetzt"
//! section of `todo.md`.

use std::cell::Cell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use semver::{Version, VersionReq};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::finding::{Finding, Location, Origin, Severity};
use crate::ingest::{CrateInfo, DeclaredDependency, Workspace};

pub const NAME_COLLISION_RISK_RULE: &str = "name-collision-risk";
/// Bump when the rule's logic changes (see todo.md §5 "Regelversions-Schutz").
pub const NAME_COLLISION_RISK_RULE_REVISION: u32 = 1;

pub const PHANTOM_CRATE_RULE: &str = "phantom-crate";
pub const PHANTOM_CRATE_RULE_REVISION: u32 = 1;

pub const PHANTOM_VERSION_RULE: &str = "phantom-version";
pub const PHANTOM_VERSION_RULE_REVISION: u32 = 1;

pub const FRESH_LOW_REPUTATION_DEP_RULE: &str = "fresh-low-reputation-dep";
pub const FRESH_LOW_REPUTATION_DEP_RULE_REVISION: u32 = 1;

/// Manually curated, offline snapshot of well-known crates.io crate names —
/// see the header comment in the file itself for the staleness caveat. This
/// is what keeps `name-collision-risk` fully local (todo.md §1 "lokal,
/// deterministisch").
const POPULAR_CRATES_RAW: &str = include_str!("data/popular_crates.txt");

// ---------------------------------------------------------------------
// Phase 1: name-collision-risk (fully local)
// ---------------------------------------------------------------------

/// Below this length, a declared dependency name is never checked for
/// collision risk — too many legitimate short-name collisions in a small
/// ecosystem (e.g. `nom` vs `norm`) to make the signal useful.
const MIN_NAME_LEN_FOR_COLLISION_CHECK: usize = 6;
/// Maximum Levenshtein distance that counts as a collision risk.
const MAX_COLLISION_EDIT_DISTANCE: usize = 1;

fn popular_crate_names() -> impl Iterator<Item = &'static str> {
    POPULAR_CRATES_RAW
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

/// Normalizes a crate name for comparison: lowercase, `-` folded to `_`.
fn normalize(name: &str) -> String {
    name.to_lowercase().replace('-', "_")
}

/// Whether `a` and `b` are the same crate (after normalizing), or one is the
/// other with a trailing `_<suffix>` removed — e.g. `serde` vs `serde_json`,
/// `tokio` vs `tokio-util`. These are not collision risks, they're
/// legitimate same-family crates.
fn is_family_pair(a: &str, b: &str) -> bool {
    let (na, nb) = (normalize(a), normalize(b));
    na == nb || na.starts_with(&format!("{nb}_")) || nb.starts_with(&format!("{na}_"))
}

/// Classic Levenshtein edit distance (insert/delete/substitute), computed
/// over `char`s so multi-byte names aren't miscounted.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        curr[0] = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

/// Runs `name-collision-risk` over every declared dependency in `workspace`.
/// Fully local — no network access, deterministic given the bundled crate
/// list.
pub fn analyze_name_collision(workspace: &Workspace) -> Vec<Finding> {
    let popular: Vec<&str> = popular_crate_names().collect();
    let mut findings = Vec::new();

    for krate in &workspace.crates {
        for dep in &krate.dependencies {
            if dep.name.len() < MIN_NAME_LEN_FOR_COLLISION_CHECK {
                continue;
            }
            let normalized_dep = normalize(&dep.name);

            let mut nearest: Option<(&str, usize)> = None;
            for &popular_name in &popular {
                if is_family_pair(&dep.name, popular_name) {
                    continue;
                }
                let distance = levenshtein(&normalized_dep, &normalize(popular_name));
                if distance == 0 || distance > MAX_COLLISION_EDIT_DISTANCE {
                    continue;
                }
                if nearest.is_none_or(|(_, best)| distance < best) {
                    nearest = Some((popular_name, distance));
                }
            }

            if let Some((nearest_name, distance)) = nearest {
                findings.push(name_collision_finding(krate, dep, nearest_name, distance));
            }
        }
    }

    findings
}

/// Renders a `name-collision-risk` finding. Confidence is deliberately low
/// (`0.45`) — edit-distance proximity is a heuristic prone to false
/// positives (unrelated crates just happen to be a typo apart), not proof of
/// typosquatting.
fn name_collision_finding(
    krate: &CrateInfo,
    dep: &DeclaredDependency,
    nearest_popular_crate: &str,
    edit_distance: usize,
) -> Finding {
    Finding {
        id: format!("{NAME_COLLISION_RISK_RULE}:{}:{}", krate.name, dep.name),
        rule: NAME_COLLISION_RISK_RULE.to_string(),
        severity: Severity::Warn,
        location: Location {
            file: krate.manifest_path.clone(),
            line: 1,
            item_path: dep.name.clone(),
        },
        confidence: 0.45,
        origin: Origin::Code,
        evidence: Some(serde_json::json!({
            "nearest_popular_crate": nearest_popular_crate,
            "edit_distance": edit_distance,
        })),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

// ---------------------------------------------------------------------
// Phase 2: shared crates.io lookup infrastructure
// ---------------------------------------------------------------------

/// A failure from a crates.io lookup — never a panic, never
/// `std::process::exit` (exit code 2 stays reserved for config/toolchain/
/// parse failures at the CLI layer, per todo.md §6; a network hiccup
/// checking a dependency is not that category of error).
#[derive(Debug)]
pub enum SlopsquatError {
    /// A connection-level failure — DNS, connect timeout, TLS handshake,
    /// and similar. Distinct from a 404 (a valid "crate not found"
    /// response), because it means the network itself isn't reachable, not
    /// that this particular crate doesn't exist.
    Connection(String),
    /// The connectivity circuit breaker has already tripped (see
    /// [`SparseIndexClient`]/[`RestMetadataClient`] docs) — no network
    /// attempt was made for this call.
    CircuitOpen,
    /// Any other network/parse failure for this specific lookup (e.g. an
    /// unexpected HTTP status, a response body that couldn't be read).
    Other(String),
}

impl std::fmt::Display for SlopsquatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connection(msg) => write!(f, "crates.io unreachable: {msg}"),
            Self::CircuitOpen => {
                write!(
                    f,
                    "crates.io lookups skipped after an earlier connection failure"
                )
            }
            Self::Other(msg) => write!(f, "crates.io lookup failed: {msg}"),
        }
    }
}

impl std::error::Error for SlopsquatError {}

/// One published version, as recorded in the crates.io sparse index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexVersion {
    pub vers: String,
    #[serde(default)]
    pub yanked: bool,
}

/// The result of a sparse-index lookup for a crate that exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub versions: Vec<IndexVersion>,
}

/// Abstracts the crates.io sparse-index lookup so `phantom-crate`/
/// `phantom-version` can be tested against fixture data — no test ever
/// constructs a [`SparseIndexClient`] or touches the real network.
pub trait CratesIoIndex {
    /// `Ok(None)` means "crate does not exist" (a 404 from the index). Any
    /// other failure — network or parse — is `Err`.
    fn lookup(&self, crate_name: &str) -> Result<Option<IndexEntry>, SlopsquatError>;
}

/// The subset of crates.io REST API fields `fresh-low-reputation-dep` needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateMetadata {
    pub created_at: String,
    pub downloads: u64,
    pub repository: Option<String>,
}

/// Abstracts the crates.io REST metadata lookup, mirroring
/// [`CratesIoIndex`]'s shape — kept as a sibling trait rather than folded
/// into `CratesIoIndex` because it hits a different API
/// (`crates.io/api/v1/crates/{name}`, not the sparse index) and returns
/// different data.
pub trait CratesIoMetadata {
    fn metadata(&self, crate_name: &str) -> Result<Option<CrateMetadata>, SlopsquatError>;
}

/// A `raw fetched entry + fetched_at` on-disk cache record (see todo.md §5
/// "Cache" for the general blake3-based pattern this deliberately deviates
/// from — there's no local file content to hash here, so the crate name
/// string itself is the cache key). TTL is [`CACHE_TTL_SECS`].
#[derive(Debug, Serialize, Deserialize)]
struct CacheRecord<T> {
    fetched_at: u64,
    data: T,
}

const CACHE_TTL_SECS: u64 = 24 * 60 * 60;

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `target/judge/slopsquat-cache/<category>/<crate-name>.json` — hardcoded,
/// not routed through a generic `--cache-dir`-configurable cache module
/// (smallest reasonable path; a future generic cache module can absorb this
/// directory later if needed). `category` separates the sparse-index cache
/// from the REST-metadata cache so the two don't collide on the same crate
/// name.
fn cache_path(cache_root: &Path, category: &str, crate_name: &str) -> PathBuf {
    cache_root.join(category).join(format!("{crate_name}.json"))
}

fn read_cache<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let text = std::fs::read_to_string(path).ok()?;
    let record: CacheRecord<T> = serde_json::from_str(&text).ok()?;
    if now_unix_secs().saturating_sub(record.fetched_at) > CACHE_TTL_SECS {
        return None;
    }
    Some(record.data)
}

/// Best-effort: a cache write failure doesn't fail the lookup it's caching.
fn write_cache<T: Serialize>(path: &Path, data: &T) {
    let record = CacheRecord {
        fetched_at: now_unix_secs(),
        data,
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(text) = serde_json::to_string(&record) {
        let _ = std::fs::write(path, text);
    }
}

/// Classifies a `ureq` error as connection-level (DNS failure, connect
/// timeout, TLS handshake failure, request timeout — the network itself
/// isn't reachable) vs. anything else (bad status, protocol error, etc.).
fn is_connection_error(err: &ureq::Error) -> bool {
    matches!(
        err,
        ureq::Error::Io(_)
            | ureq::Error::HostNotFound
            | ureq::Error::ConnectionFailed
            | ureq::Error::Timeout(_)
    )
}

fn build_agent(user_agent: &str) -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(3)))
        .timeout_global(Some(Duration::from_secs(5)))
        .user_agent(user_agent)
        .build();
    config.into()
}

/// User-Agent sent on every request, per crates.io's crawler policy (a
/// descriptive UA identifying the tool and a way to reach its maintainers).
const JUDGE_USER_AGENT: &str = "cargo-judge (https://github.com/casoon/judge)";

/// Builds the crates.io sparse-index path for `crate_name`, per crates.io's
/// directory convention: 1-char names go in `1/<name>`, 2-char in
/// `2/<name>`, 3-char in `3/<first-char>/<name>`, 4+ chars in
/// `<first-two>/<next-two>/<name>`. Crate names are lowercased for the path,
/// matching cargo's own sparse-index client behavior.
fn sparse_index_path(crate_name: &str) -> String {
    let lower = crate_name.to_lowercase();
    match lower.len() {
        0 => format!("1/{lower}"),
        1 => format!("1/{lower}"),
        2 => format!("2/{lower}"),
        3 => format!("3/{}/{lower}", &lower[..1]),
        _ => format!("{}/{}/{lower}", &lower[..2], &lower[2..4]),
    }
}

/// One line of the sparse index's JSON-lines response body — only the
/// fields judge needs are captured; extra fields (`deps`, `cksum`,
/// `features`, ...) are ignored by `serde_json` automatically.
#[derive(Debug, Deserialize)]
struct RawIndexLine {
    vers: String,
    #[serde(default)]
    yanked: bool,
}

/// Real [`CratesIoIndex`] implementation: fetches
/// `https://index.crates.io/<path>` via a short-timeout `ureq::Agent`.
///
/// Connectivity short-circuit: the first lookup that fails with a
/// connection-level error (not a 404, which is a valid "not found" answer)
/// trips the breaker for the rest of this client's lifetime — every
/// subsequent call returns [`SlopsquatError::CircuitOpen`] without
/// attempting the network. One connection failure is treated as good
/// evidence there's no network available at all for the rest of this run;
/// retrying per-dependency would just flood the output with the same
/// failure N times for no benefit.
pub struct SparseIndexClient {
    agent: ureq::Agent,
    cache_root: PathBuf,
    circuit_open: Cell<bool>,
}

impl SparseIndexClient {
    pub fn new(cache_root: PathBuf) -> Self {
        Self {
            agent: build_agent(JUDGE_USER_AGENT),
            cache_root,
            circuit_open: Cell::new(false),
        }
    }
}

impl CratesIoIndex for SparseIndexClient {
    fn lookup(&self, crate_name: &str) -> Result<Option<IndexEntry>, SlopsquatError> {
        let path = cache_path(&self.cache_root, "index", crate_name);
        if let Some(cached) = read_cache::<Option<IndexEntry>>(&path) {
            return Ok(cached);
        }
        if self.circuit_open.get() {
            return Err(SlopsquatError::CircuitOpen);
        }

        let url = format!("https://index.crates.io/{}", sparse_index_path(crate_name));
        let mut response = match self.agent.get(&url).call() {
            Ok(response) => response,
            Err(ureq::Error::StatusCode(404)) => {
                write_cache(&path, &None::<IndexEntry>);
                return Ok(None);
            }
            Err(err) if is_connection_error(&err) => {
                self.circuit_open.set(true);
                return Err(SlopsquatError::Connection(err.to_string()));
            }
            Err(err) => return Err(SlopsquatError::Other(err.to_string())),
        };

        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|err| SlopsquatError::Other(err.to_string()))?;

        // Each line is an independent JSON object; a malformed line is
        // skipped rather than failing the whole fetch.
        let versions: Vec<IndexVersion> = body
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str::<RawIndexLine>(line).ok())
            .map(|raw| IndexVersion {
                vers: raw.vers,
                yanked: raw.yanked,
            })
            .collect();

        let entry = IndexEntry { versions };
        write_cache(&path, &Some(entry.clone()));
        Ok(Some(entry))
    }
}

/// The crates.io REST API's `{"crate": {...}}` envelope — only the fields
/// [`CrateMetadata`] needs are captured.
#[derive(Debug, Deserialize)]
struct RestCrateResponse {
    #[serde(rename = "crate")]
    krate: CrateMetadata,
}

/// Real [`CratesIoMetadata`] implementation: fetches
/// `https://crates.io/api/v1/crates/{name}` via a short-timeout
/// `ureq::Agent`. Same connectivity short-circuit behavior as
/// [`SparseIndexClient`] — see its docs — but tracked independently, since
/// this is a separate network call path (a different host/API) that can
/// fail on its own.
pub struct RestMetadataClient {
    agent: ureq::Agent,
    cache_root: PathBuf,
    circuit_open: Cell<bool>,
}

impl RestMetadataClient {
    pub fn new(cache_root: PathBuf) -> Self {
        Self {
            agent: build_agent(JUDGE_USER_AGENT),
            cache_root,
            circuit_open: Cell::new(false),
        }
    }
}

impl CratesIoMetadata for RestMetadataClient {
    fn metadata(&self, crate_name: &str) -> Result<Option<CrateMetadata>, SlopsquatError> {
        let path = cache_path(&self.cache_root, "meta", crate_name);
        if let Some(cached) = read_cache::<Option<CrateMetadata>>(&path) {
            return Ok(cached);
        }
        if self.circuit_open.get() {
            return Err(SlopsquatError::CircuitOpen);
        }

        let url = format!("https://crates.io/api/v1/crates/{crate_name}");
        let mut response = match self.agent.get(&url).call() {
            Ok(response) => response,
            Err(ureq::Error::StatusCode(404)) => {
                write_cache(&path, &None::<CrateMetadata>);
                return Ok(None);
            }
            Err(err) if is_connection_error(&err) => {
                self.circuit_open.set(true);
                return Err(SlopsquatError::Connection(err.to_string()));
            }
            Err(err) => return Err(SlopsquatError::Other(err.to_string())),
        };

        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|err| SlopsquatError::Other(err.to_string()))?;
        let parsed: RestCrateResponse =
            serde_json::from_str(&body).map_err(|err| SlopsquatError::Other(err.to_string()))?;

        write_cache(&path, &Some(parsed.krate.clone()));
        Ok(Some(parsed.krate))
    }
}

/// A test-only, fully in-memory [`CratesIoIndex`] — driven from literal
/// fixture data, never touches the network.
#[derive(Default)]
pub struct FixtureIndex {
    crates: HashMap<String, Vec<IndexVersion>>,
    /// If set, every lookup fails with this error instead of consulting
    /// `crates` — used to test error propagation without a real network.
    forced_error: Option<String>,
}

impl FixtureIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_crate(mut self, name: &str, versions: Vec<IndexVersion>) -> Self {
        self.crates.insert(name.to_string(), versions);
        self
    }

    pub fn with_error(mut self, message: &str) -> Self {
        self.forced_error = Some(message.to_string());
        self
    }
}

impl CratesIoIndex for FixtureIndex {
    fn lookup(&self, crate_name: &str) -> Result<Option<IndexEntry>, SlopsquatError> {
        if let Some(message) = &self.forced_error {
            return Err(SlopsquatError::Other(message.clone()));
        }
        Ok(self.crates.get(crate_name).map(|versions| IndexEntry {
            versions: versions.clone(),
        }))
    }
}

/// A test-only, fully in-memory [`CratesIoMetadata`] — mirrors
/// [`FixtureIndex`].
#[derive(Default)]
pub struct FixtureMetadata {
    crates: HashMap<String, CrateMetadata>,
}

impl FixtureMetadata {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_crate(mut self, name: &str, metadata: CrateMetadata) -> Self {
        self.crates.insert(name.to_string(), metadata);
        self
    }
}

impl CratesIoMetadata for FixtureMetadata {
    fn metadata(&self, crate_name: &str) -> Result<Option<CrateMetadata>, SlopsquatError> {
        Ok(self.crates.get(crate_name).cloned())
    }
}

// ---------------------------------------------------------------------
// Phase 3: phantom-crate / phantom-version
// ---------------------------------------------------------------------

/// Findings plus non-fatal errors from a network-dependent slopsquat pass —
/// mirrors `deps::WorkspaceDeps`'s `findings`/`errors` shape.
#[derive(Debug, Default)]
pub struct SlopsquatNetworkReport {
    pub findings: Vec<Finding>,
    pub errors: Vec<String>,
}

/// Runs `phantom-crate` and `phantom-version` over every declared
/// dependency in `workspace`, via `index`. One sparse-index lookup covers
/// both rules per dependency.
pub fn analyze_phantom_dependencies(
    workspace: &Workspace,
    index: &dyn CratesIoIndex,
) -> SlopsquatNetworkReport {
    let mut report = SlopsquatNetworkReport::default();
    let mut connection_error_reported = false;

    for krate in &workspace.crates {
        for dep in &krate.dependencies {
            match index.lookup(&dep.name) {
                Ok(None) => report.findings.push(phantom_crate_finding(krate, dep)),
                Ok(Some(entry)) => {
                    if let Some(finding) = phantom_version_finding(krate, dep, &entry) {
                        report.findings.push(finding);
                    }
                }
                Err(SlopsquatError::CircuitOpen) => {}
                Err(SlopsquatError::Connection(msg)) => {
                    if !connection_error_reported {
                        report.errors.push(format!(
                            "crates.io sparse index unreachable, skipping remaining phantom-crate/phantom-version checks: {msg}"
                        ));
                        connection_error_reported = true;
                    }
                }
                Err(SlopsquatError::Other(msg)) => {
                    report
                        .errors
                        .push(format!("{}: crates.io lookup failed: {msg}", dep.name));
                }
            }
        }
    }

    report
}

fn phantom_crate_finding(krate: &CrateInfo, dep: &DeclaredDependency) -> Finding {
    Finding {
        id: format!("{PHANTOM_CRATE_RULE}:{}:{}", krate.name, dep.name),
        rule: PHANTOM_CRATE_RULE.to_string(),
        severity: Severity::Fail,
        location: Location {
            file: krate.manifest_path.clone(),
            line: 1,
            item_path: dep.name.clone(),
        },
        confidence: 0.9,
        origin: Origin::Code,
        evidence: Some(serde_json::json!({
            "lookup": "sparse-index",
            "result": "not_found",
        })),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// `None` if the declared requirement is satisfied by some published,
/// non-yanked version (or if the requirement string doesn't parse — judge
/// doesn't assert a claim it can't back with a real comparison).
fn phantom_version_finding(
    krate: &CrateInfo,
    dep: &DeclaredDependency,
    entry: &IndexEntry,
) -> Option<Finding> {
    let Ok(req) = VersionReq::parse(&dep.version_req) else {
        return None;
    };

    let published: Vec<&IndexVersion> = entry.versions.iter().filter(|v| !v.yanked).collect();
    let satisfied = published
        .iter()
        .any(|v| Version::parse(&v.vers).is_ok_and(|version| req.matches(&version)));
    if satisfied {
        return None;
    }

    Some(Finding {
        id: format!("{PHANTOM_VERSION_RULE}:{}:{}", krate.name, dep.name),
        rule: PHANTOM_VERSION_RULE.to_string(),
        severity: Severity::Fail,
        location: Location {
            file: krate.manifest_path.clone(),
            line: 1,
            item_path: dep.name.clone(),
        },
        confidence: 0.85,
        origin: Origin::Code,
        evidence: Some(serde_json::json!({
            "requirement": dep.version_req,
            "nearest_published_versions": nearest_versions(&published, 3),
        })),
        caused_by: Vec::new(),
        causes: Vec::new(),
    })
}

/// Up to `limit` published version strings, highest-first by parsed semver
/// (versions that fail to parse are dropped from this evidence list, not
/// from correctness — `phantom_version_finding`'s `satisfied` check above
/// already treated them as non-matching).
fn nearest_versions(published: &[&IndexVersion], limit: usize) -> Vec<String> {
    let mut parsed: Vec<(Version, &str)> = published
        .iter()
        .filter_map(|v| {
            Version::parse(&v.vers)
                .ok()
                .map(|version| (version, v.vers.as_str()))
        })
        .collect();
    parsed.sort_by(|a, b| b.0.cmp(&a.0));
    parsed
        .into_iter()
        .take(limit)
        .map(|(_, raw)| raw.to_string())
        .collect()
}

// ---------------------------------------------------------------------
// Phase 4: fresh-low-reputation-dep
// ---------------------------------------------------------------------

/// The `judge.toml` `[slopsquat]` table (see todo.md §8).
#[derive(Debug, Clone, Deserialize)]
pub struct SlopsquatConfig {
    /// `fresh-low-reputation-dep` flags a dependency once its crates.io
    /// download count is below this, combined with the age and
    /// no-repository conditions (see [`analyze_fresh_low_reputation`]).
    #[serde(default = "SlopsquatConfig::default_min_downloads")]
    pub min_downloads: u64,
}

impl SlopsquatConfig {
    fn default_min_downloads() -> u64 {
        DEFAULT_MIN_DOWNLOADS
    }
}

impl Default for SlopsquatConfig {
    fn default() -> Self {
        Self {
            min_downloads: Self::default_min_downloads(),
        }
    }
}

const DEFAULT_MIN_DOWNLOADS: u64 = 1000;
/// A crate younger than this many days counts as "fresh" for
/// `fresh-low-reputation-dep`.
const FRESH_AGE_DAYS: i64 = 90;

/// Runs `fresh-low-reputation-dep` over every declared dependency in
/// `workspace`, via `metadata_source`. Flags a dependency only when *all
/// three* conditions hold together: age < 90 days, downloads <
/// `config.min_downloads`, and no `repository` field (see todo.md §14.2 G5
/// — read as an AND of all three; using OR would flag most legitimate small
/// crates, many of which simply don't set `repository`).
pub fn analyze_fresh_low_reputation(
    workspace: &Workspace,
    metadata_source: &dyn CratesIoMetadata,
    config: &SlopsquatConfig,
) -> SlopsquatNetworkReport {
    let mut report = SlopsquatNetworkReport::default();
    let mut connection_error_reported = false;

    for krate in &workspace.crates {
        for dep in &krate.dependencies {
            match metadata_source.metadata(&dep.name) {
                Ok(Some(metadata)) => {
                    if is_fresh_low_reputation(&metadata, config) {
                        report
                            .findings
                            .push(fresh_low_reputation_finding(krate, dep, &metadata));
                    }
                }
                Ok(None) => {}
                Err(SlopsquatError::CircuitOpen) => {}
                Err(SlopsquatError::Connection(msg)) => {
                    if !connection_error_reported {
                        report.errors.push(format!(
                            "crates.io API unreachable, skipping remaining fresh-low-reputation-dep checks: {msg}"
                        ));
                        connection_error_reported = true;
                    }
                }
                Err(SlopsquatError::Other(msg)) => {
                    report.errors.push(format!(
                        "{}: crates.io metadata lookup failed: {msg}",
                        dep.name
                    ));
                }
            }
        }
    }

    report
}

fn is_fresh_low_reputation(metadata: &CrateMetadata, config: &SlopsquatConfig) -> bool {
    let Some(created_unix) = parse_rfc3339_to_unix_seconds(&metadata.created_at) else {
        return false;
    };
    let age_days = (now_unix_secs() as i64 - created_unix) / 86_400;
    let is_fresh = age_days < FRESH_AGE_DAYS;
    let is_low_downloads = metadata.downloads < config.min_downloads;
    let has_no_repo = metadata
        .repository
        .as_ref()
        .is_none_or(|repo| repo.trim().is_empty());
    is_fresh && is_low_downloads && has_no_repo
}

fn fresh_low_reputation_finding(
    krate: &CrateInfo,
    dep: &DeclaredDependency,
    metadata: &CrateMetadata,
) -> Finding {
    Finding {
        id: format!(
            "{FRESH_LOW_REPUTATION_DEP_RULE}:{}:{}",
            krate.name, dep.name
        ),
        rule: FRESH_LOW_REPUTATION_DEP_RULE.to_string(),
        severity: Severity::Warn,
        location: Location {
            file: krate.manifest_path.clone(),
            line: 1,
            item_path: dep.name.clone(),
        },
        confidence: 0.6,
        origin: Origin::Code,
        evidence: Some(serde_json::json!({
            "created_at": metadata.created_at,
            "downloads": metadata.downloads,
            "repository": metadata.repository,
        })),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// Parses an RFC 3339 timestamp's date/time portion (`YYYY-MM-DDTHH:MM:SS`,
/// ignoring any fractional seconds/offset suffix) into Unix seconds. Good
/// enough for the day-granularity age check `fresh-low-reputation-dep`
/// needs — not a general RFC 3339 parser. Deliberately hand-rolled (via the
/// well-known `days_from_civil` algorithm) rather than pulling in a
/// `chrono`/`time` dependency just for this one comparison.
fn parse_rfc3339_to_unix_seconds(s: &str) -> Option<i64> {
    if s.len() < 19 {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let minute: i64 = s.get(14..16)?.parse().ok()?;
    let second: i64 = s.get(17..19)?.parse().ok()?;
    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Howard Hinnant's `days_from_civil` algorithm: days since 1970-01-01 for
/// a proleptic-Gregorian `(year, month, day)`. Correct for any year, no
/// external date library needed.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    fn write_manifest(dir: &TempDir, deps: &[(&str, &str)]) -> PathBuf {
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn hello() {}\n").unwrap();
        let dep_lines: String = deps
            .iter()
            .map(|(name, req)| format!("{name} = \"{req}\"\n"))
            .collect();
        std::fs::write(
            dir.join("Cargo.toml"),
            format!(
                r#"
[package]
name = "fixture"
version = "0.1.0"
edition = "2021"

[dependencies]
{dep_lines}
"#
            ),
        )
        .unwrap();
        dir.join("Cargo.toml")
    }

    // -- name-collision-risk --

    #[test]
    fn a_near_miss_name_is_flagged() {
        let dir = TempDir::new("slopsquat-collision-near-miss");
        // "reqwests" is one insertion away from the real "reqwest", and
        // (unlike a name like "toko" vs "tokio") both names clear the
        // length-6 floor, so the length gate doesn't hide the collision.
        let manifest = write_manifest(&dir, &[("reqwests", "1.0")]);
        let workspace = crate::ingest::load(Some(&manifest)).unwrap();

        let findings = analyze_name_collision(&workspace);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, NAME_COLLISION_RISK_RULE);
        assert_eq!(findings[0].location.item_path, "reqwests");
        let evidence = findings[0].evidence.as_ref().unwrap();
        assert_eq!(evidence["nearest_popular_crate"], "reqwest");
        assert_eq!(evidence["edit_distance"], 1);
    }

    #[test]
    fn a_same_family_pair_is_not_flagged() {
        let dir = TempDir::new("slopsquat-collision-family");
        // "serde_jsonx" is 1 edit away from the real "serde_json", but it's
        // a same-family suffix-style name, not a fair comparison target
        // here — use a real family example instead: "tokio_util" is exactly
        // the popular "tokio-util" name (normalized), so it's excluded as
        // an exact/family match, not a collision.
        let manifest = write_manifest(&dir, &[("tokio_util", "1.0")]);
        let workspace = crate::ingest::load(Some(&manifest)).unwrap();

        let findings = analyze_name_collision(&workspace);

        assert!(findings.is_empty());
    }

    #[test]
    fn short_names_are_never_flagged() {
        let dir = TempDir::new("slopsquat-collision-short");
        // "rand" -> distance 1 from "rank" would be a collision candidate
        // if length didn't disable the check; "rand" itself is only 4
        // characters, below the length-6 floor.
        let manifest = write_manifest(&dir, &[("rand", "1.0")]);
        let workspace = crate::ingest::load(Some(&manifest)).unwrap();

        let findings = analyze_name_collision(&workspace);

        assert!(findings.is_empty());
    }

    #[test]
    fn an_exact_match_to_a_popular_name_is_not_flagged() {
        let dir = TempDir::new("slopsquat-collision-exact");
        let manifest = write_manifest(&dir, &[("reqwest", "1.0")]);
        let workspace = crate::ingest::load(Some(&manifest)).unwrap();

        let findings = analyze_name_collision(&workspace);

        assert!(findings.is_empty());
    }

    #[test]
    fn levenshtein_matches_known_distances() {
        assert_eq!(levenshtein("toko", "tokio"), 1);
        assert_eq!(levenshtein("reqwest", "reqwest"), 0);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
    }

    // -- phantom-crate / phantom-version --

    #[test]
    fn an_existing_crate_with_a_satisfied_requirement_has_no_finding() {
        let dir = TempDir::new("slopsquat-phantom-ok");
        let manifest = write_manifest(&dir, &[("widgetcrate", "1.0")]);
        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let index = FixtureIndex::new().with_crate(
            "widgetcrate",
            vec![IndexVersion {
                vers: "1.2.0".to_string(),
                yanked: false,
            }],
        );

        let report = analyze_phantom_dependencies(&workspace, &index);

        assert!(report.findings.is_empty());
        assert!(report.errors.is_empty());
    }

    #[test]
    fn a_nonexistent_crate_name_is_a_phantom_crate_finding() {
        let dir = TempDir::new("slopsquat-phantom-crate");
        let manifest = write_manifest(&dir, &[("totally-hallucinated-crate", "1.0")]);
        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let index = FixtureIndex::new();

        let report = analyze_phantom_dependencies(&workspace, &index);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule, PHANTOM_CRATE_RULE);
        assert_eq!(report.findings[0].severity, Severity::Fail);
    }

    #[test]
    fn a_requirement_with_no_satisfying_published_version_is_a_phantom_version_finding() {
        let dir = TempDir::new("slopsquat-phantom-version");
        let manifest = write_manifest(&dir, &[("widgetcrate", "99.0")]);
        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let index = FixtureIndex::new().with_crate(
            "widgetcrate",
            vec![IndexVersion {
                vers: "1.2.0".to_string(),
                yanked: false,
            }],
        );

        let report = analyze_phantom_dependencies(&workspace, &index);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule, PHANTOM_VERSION_RULE);
        assert_eq!(report.findings[0].severity, Severity::Fail);
    }

    #[test]
    fn an_index_lookup_error_surfaces_as_an_error_with_no_findings_and_no_panic() {
        let dir = TempDir::new("slopsquat-phantom-error");
        let manifest = write_manifest(&dir, &[("widgetcrate", "1.0")]);
        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let index = FixtureIndex::new().with_error("simulated failure");

        let report = analyze_phantom_dependencies(&workspace, &index);

        assert!(report.findings.is_empty());
        assert_eq!(report.errors.len(), 1);
    }

    // -- fresh-low-reputation-dep --

    #[test]
    fn a_fresh_low_download_repo_less_crate_is_flagged() {
        let dir = TempDir::new("slopsquat-fresh-flagged");
        let manifest = write_manifest(&dir, &[("brandnewcrate", "1.0")]);
        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let recent = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 10 * 86_400; // 10 days old
        let created_at = unix_seconds_to_rfc3339(recent as i64);
        let metadata_source = FixtureMetadata::new().with_crate(
            "brandnewcrate",
            CrateMetadata {
                created_at,
                downloads: 5,
                repository: None,
            },
        );
        let config = SlopsquatConfig::default();

        let report = analyze_fresh_low_reputation(&workspace, &metadata_source, &config);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule, FRESH_LOW_REPUTATION_DEP_RULE);
    }

    #[test]
    fn an_old_well_downloaded_crate_with_a_repo_is_not_flagged() {
        let dir = TempDir::new("slopsquat-fresh-ok");
        let manifest = write_manifest(&dir, &[("establishedcrate", "1.0")]);
        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let metadata_source = FixtureMetadata::new().with_crate(
            "establishedcrate",
            CrateMetadata {
                created_at: "2015-01-01T00:00:00.000000Z".to_string(),
                downloads: 50_000_000,
                repository: Some("https://github.com/example/establishedcrate".to_string()),
            },
        );
        let config = SlopsquatConfig::default();

        let report = analyze_fresh_low_reputation(&workspace, &metadata_source, &config);

        assert!(report.findings.is_empty());
    }

    #[test]
    fn min_downloads_is_configurable() {
        let dir = TempDir::new("slopsquat-fresh-configurable");
        let manifest = write_manifest(&dir, &[("midtiercrate", "1.0")]);
        let workspace = crate::ingest::load(Some(&manifest)).unwrap();
        let recent = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 5 * 86_400;
        let created_at = unix_seconds_to_rfc3339(recent as i64);
        let metadata_source = FixtureMetadata::new().with_crate(
            "midtiercrate",
            CrateMetadata {
                created_at,
                downloads: 5_000,
                repository: None,
            },
        );

        // Default threshold (1000) doesn't flag 5000 downloads.
        let default_config = SlopsquatConfig::default();
        let report = analyze_fresh_low_reputation(&workspace, &metadata_source, &default_config);
        assert!(report.findings.is_empty());

        // A higher configured threshold does.
        let strict_config = SlopsquatConfig {
            min_downloads: 10_000,
        };
        let report = analyze_fresh_low_reputation(&workspace, &metadata_source, &strict_config);
        assert_eq!(report.findings.len(), 1);
    }

    #[test]
    fn days_from_civil_matches_known_epoch_offsets() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2014, 11, 14), 16_388);
    }

    /// Test-only inverse of [`parse_rfc3339_to_unix_seconds`] — builds a
    /// timestamp string for a given Unix-seconds instant. Not exact for
    /// arbitrary instants (only needs day granularity here), but exact
    /// enough for these tests, which only care about "N days ago".
    fn unix_seconds_to_rfc3339(unix_seconds: i64) -> String {
        let days = unix_seconds.div_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        format!("{year:04}-{month:02}-{day:02}T00:00:00.000000Z")
    }

    /// Inverse of [`days_from_civil`], same Howard Hinnant algorithm family.
    fn civil_from_days(z: i64) -> (i64, i64, i64) {
        let z = z + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        (if m <= 2 { y + 1 } else { y }, m, d)
    }
}
