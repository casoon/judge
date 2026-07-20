//! Provenance attribution: heuristic author-class breakdowns of churn,
//! duplication, and suppression debt (see todo.md §3.G G6).
//!
//! Everything this module produces is `heuristic`-classed per todo.md
//! §17.2: trailer/marker *text presence* is exact (a trailer either says
//! "claude" or it doesn't), but the *inference* "this proves who wrote the
//! code" is never more than a reproducible interpretation, never a proof.
//! Commit trailers are optional, unverified, and trivially fakeable; the
//! size/timing/style heuristics are weaker still. See [`PROVENANCE_CAVEAT`],
//! which is threaded through every finding this module emits and must also
//! be shown unconditionally wherever those findings are displayed (see
//! `main.rs`'s `run_provenance`) — todo.md §3.G's explicit misuse warning:
//! this is a distribution trend, not a judgement on any single commit or
//! person.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use gix::bstr::BStr;

use crate::boundaries::ProvenanceLabel;
use crate::duplication::{CloneFamily, DupeMode, DuplicationError};
use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::git::{self, CommitInfo, GitError};
use crate::ingest::Workspace;
use crate::slop::SlopError;

/// Rule id for churn tallied by author class.
pub const PROVENANCE_CHURN_RULE: &str = "provenance-churn";
/// Bump when the churn-by-class rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const PROVENANCE_CHURN_RULE_REVISION: u32 = 1;

/// Rule id for duplication findings tallied by the author class that
/// introduced them (via blame).
pub const PROVENANCE_DUPLICATION_RATE_RULE: &str = "provenance-duplication-rate";
/// Bump when the duplication-rate-by-class rule's logic changes (see
/// todo.md §5 "Regelversions-Schutz").
pub const PROVENANCE_DUPLICATION_RATE_RULE_REVISION: u32 = 1;

/// Rule id for `suppression-debt` findings tallied by the author class that
/// introduced them (via blame).
pub const PROVENANCE_SUPPRESSION_DEBT_RULE: &str = "provenance-suppression-debt";
/// Bump when the suppression-debt-by-class rule's logic changes (see
/// todo.md §5 "Regelversions-Schutz").
pub const PROVENANCE_SUPPRESSION_DEBT_RULE_REVISION: u32 = 1;

/// The misuse-warning caveat mandated by todo.md §3.G G6. Must appear in
/// every finding's evidence, as an unconditional TTY header, and as a
/// top-level JSON envelope field — see `main.rs`'s `run_provenance`.
pub const PROVENANCE_CAVEAT: &str = "Provenance labels are a distribution trend, not a judgment on any single commit or person. Trailers and metadata are incomplete and can be manipulated; the heuristics are weak. Valid as a trend, not valid as a gate. Using this to evaluate individual people is a misuse of this tool.";

/// Minimum in-window commit count before the commit-size outlier check runs
/// at all — small-sample honesty, mirroring `audit --since`'s own
/// `--audit-min-sample` precedent. First-cut constant, not yet
/// configurable (matches this session's `CHURN_HOTSPOT_THRESHOLD`/
/// `MIN_LOC_FOR_INFLATION` pattern for v1 thresholds).
const MIN_COMMITS_FOR_SIZE_OUTLIER: usize = 10;
/// Standard-deviation multiplier above the mean file-count that flags a
/// commit's size as an outlier.
const SIZE_OUTLIER_STDDEV_MULTIPLIER: f64 = 2.0;
/// Minimum in-window commit count, per author, before the inter-commit
/// interval coefficient-of-variation check runs for that author.
const MIN_COMMITS_FOR_INTERVAL_CV: usize = 5;
/// Coefficient-of-variation threshold below which an author's commit
/// cadence is flagged as suspiciously regular.
const INTERVAL_CV_THRESHOLD: f64 = 0.15;

/// Confidence assigned to a trailer/marker match (see todo.md §3.G: "Labels
/// sind das präzisere Signal" — trailers are the next tier down).
const TRAILER_CONFIDENCE: f32 = 0.85;
/// Confidence assigned to a configured `[[provenance_label]]` match — forced
/// higher than a trailer match per the plan's confirmed precedence.
const LABEL_CONFIDENCE: f32 = 0.95;
/// Confidence assigned to a heuristic-only match (size/timing/style, no
/// trailer or label) — the weakest tier.
const HEURISTIC_CONFIDENCE: f32 = 0.35;

/// The author class a commit is classified into. Deliberately has no
/// `Human` variant: absence of a trailer/label/heuristic signal is not proof
/// of human authorship, only absence of evidence either way.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AuthorClass {
    /// A named coding agent/bot (`"claude"`, `"copilot"`, `"cursor"`, or the
    /// generic heuristic fallback `"bot"`).
    Agent(String),
    /// Matched a user-configured `[[provenance_label]]` — name is
    /// user-chosen.
    Labeled(String),
    /// No label, trailer, marker, or heuristic signal fired.
    Unknown,
}

impl AuthorClass {
    /// A stable, finding-id-safe key for this class (`"agent-claude"`,
    /// `"labeled-contractor-x"`, `"unknown"`).
    pub fn key(&self) -> String {
        match self {
            Self::Agent(name) => format!("agent-{name}"),
            Self::Labeled(name) => format!("labeled-{name}"),
            Self::Unknown => "unknown".to_string(),
        }
    }
}

/// One commit's classification: its [`AuthorClass`], confidence, and the
/// evidence backing it.
type Classification = (AuthorClass, f32, serde_json::Value);

/// Per-class aggregate counts across the three metrics this module
/// breaks down (see todo.md §3.G G6).
#[derive(Debug, Clone)]
pub struct ClassSummary {
    pub class: AuthorClass,
    pub churn: u32,
    pub duplication: u32,
    pub suppression_debt: u32,
    /// The minimum per-commit classification confidence among every commit
    /// that contributed to this class's counts — conservative on purpose:
    /// a class bucket is only as trustworthy as its weakest evidence (e.g.
    /// `Agent("bot")` can be reached both via a `bot`/`ai-assistant`
    /// trailer at `0.85` and via heuristics alone at `0.35`; the bucket
    /// must report the lower number, not average it away).
    pub confidence: f32,
}

/// A failure in one of the analyses this module composes, kept separate
/// from a top-level fatal error the same way `ownership::OwnershipError`
/// is — a failure blaming one file shouldn't drop the whole report.
#[derive(Debug)]
pub enum ProvenanceError {
    Git(GitError),
    Duplication(DuplicationError),
    Slop(SlopError),
}

impl std::fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Git(err) => write!(f, "{err}"),
            Self::Duplication(err) => write!(f, "{err}"),
            Self::Slop(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ProvenanceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Git(err) => Some(err),
            Self::Duplication(err) => Some(err),
            Self::Slop(err) => Some(err),
        }
    }
}

/// Everything `cargo judge provenance` reports: one [`Finding`] per
/// non-zero `(metric, AuthorClass)` combination, the raw per-class counts
/// behind them, and any analysis errors (see `main.rs`'s `run_provenance`).
pub struct ProvenanceBreakdown {
    pub findings: Vec<Finding>,
    pub by_class: Vec<ClassSummary>,
    pub errors: Vec<ProvenanceError>,
}

/// Runs the full G6 pipeline over `workspace`: walks commit history,
/// classifies every commit by author class (labels, then trailers/markers,
/// then heuristics), and breaks churn, duplication, and suppression debt
/// down by class.
pub fn analyze_workspace(
    workspace: &Workspace,
    window_days: i64,
    labels: &[ProvenanceLabel],
) -> ProvenanceBreakdown {
    let mut errors = Vec::new();

    let commits = match git::walk_commits(&workspace.root, window_days) {
        Ok(commits) => commits,
        Err(err) => {
            errors.push(ProvenanceError::Git(err));
            Vec::new()
        }
    };

    let classes = classify_commits(&commits, labels);
    let churn = churn_by_class(&commits, &classes);

    let dupes_source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    let dupes = crate::duplication::analyze_workspace(
        dupes_source_files,
        DupeMode::Mild,
        crate::duplication::DEFAULT_MIN_TOKENS,
        false,
    );
    errors.extend(dupes.errors.into_iter().map(ProvenanceError::Duplication));

    let duplication = match duplication_rate_by_class(&dupes.families, &workspace.root, &classes) {
        Ok(counts) => counts,
        Err(err) => {
            errors.push(ProvenanceError::Git(err));
            HashMap::new()
        }
    };

    let slop_source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    let slop_report = crate::slop::analyze_workspace(slop_source_files, false, false);
    errors.extend(slop_report.errors.into_iter().map(ProvenanceError::Slop));
    let suppression_findings: Vec<Finding> = slop_report
        .findings
        .into_iter()
        .filter(|finding| finding.rule == crate::slop::SUPPRESSION_DEBT_RULE)
        .collect();

    let suppression =
        match suppression_debt_by_class(&suppression_findings, &workspace.root, &classes) {
            Ok(counts) => counts,
            Err(err) => {
                errors.push(ProvenanceError::Git(err));
                HashMap::new()
            }
        };

    let mut all_classes: HashSet<AuthorClass> = HashSet::new();
    all_classes.extend(churn.keys().cloned());
    all_classes.extend(duplication.keys().cloned());
    all_classes.extend(suppression.keys().cloned());

    // Minimum per-commit confidence contributing to each class, so a bucket
    // that mixes e.g. trailer-based (0.85) and heuristic-only (0.35) hits
    // for the same `AuthorClass` reports the weaker number, not the
    // stronger one (see `ClassSummary::confidence`'s doc comment).
    let mut min_confidence: HashMap<AuthorClass, f32> = HashMap::new();
    for (class, confidence, _) in classes.values() {
        min_confidence
            .entry(class.clone())
            .and_modify(|existing| *existing = existing.min(*confidence))
            .or_insert(*confidence);
    }

    let mut by_class: Vec<ClassSummary> = all_classes
        .into_iter()
        .map(|class| ClassSummary {
            churn: churn.get(&class).copied().unwrap_or(0),
            duplication: duplication.get(&class).copied().unwrap_or(0),
            suppression_debt: suppression.get(&class).copied().unwrap_or(0),
            confidence: min_confidence.get(&class).copied().unwrap_or(1.0),
            class,
        })
        .collect();
    by_class.sort_by_key(|a| a.class.key());

    let cargo_toml = workspace.root.join("Cargo.toml");
    let findings = by_class
        .iter()
        .flat_map(|summary| summary.to_findings(&cargo_toml))
        .collect();

    ProvenanceBreakdown {
        findings,
        by_class,
        errors,
    }
}

impl ClassSummary {
    /// One [`Finding`] per metric with a non-zero count, at a sentinel
    /// workspace-level location — same pattern `boundaries.rs` uses for
    /// aggregate, not per-line, facts.
    fn to_findings(&self, cargo_toml: &Path) -> Vec<Finding> {
        let key = self.class.key();
        let mut findings = Vec::new();
        if self.churn > 0 {
            findings.push(metric_finding(
                PROVENANCE_CHURN_RULE,
                &key,
                self.churn,
                self.confidence,
                "churn",
                cargo_toml,
            ));
        }
        if self.duplication > 0 {
            findings.push(metric_finding(
                PROVENANCE_DUPLICATION_RATE_RULE,
                &key,
                self.duplication,
                self.confidence,
                "duplication",
                cargo_toml,
            ));
        }
        if self.suppression_debt > 0 {
            findings.push(metric_finding(
                PROVENANCE_SUPPRESSION_DEBT_RULE,
                &key,
                self.suppression_debt,
                self.confidence,
                "suppression debt",
                cargo_toml,
            ));
        }
        findings
    }
}

fn metric_finding(
    rule: &str,
    class_key: &str,
    count: u32,
    classification_confidence: f32,
    label: &str,
    cargo_toml: &Path,
) -> Finding {
    Finding {
        id: format!("{rule}:{class_key}").into(),
        rule: rule.into(),
        // Always Info: this is a distribution trend, never a pass/fail
        // judgement (see `PROVENANCE_CAVEAT`, todo.md §3.G G6). Relies on
        // `health_score::compute`/`baseline::Delta::verdict`'s existing
        // `Severity::Info` exclusion — see todo.md §17.2.
        severity: Severity::Info,
        location: Location {
            file: cargo_toml.to_path_buf(),
            line: OneBasedLine::FIRST,
            item_path: format!("{label} by class: {class_key}"),
        },
        // The count itself is exact, but the classification behind the
        // bucket is an interpretation of trailers/markers/heuristics —
        // never proof of authorship (todo.md §17.4), hence `Heuristic`.
        evidence_class: EvidenceClass::Heuristic,
        origin: Origin::Code,
        evidence: Some(serde_json::json!({
            "basis": "aggregate",
            "class": class_key,
            "count": count,
            // How trustworthy the *classification* behind this bucket is
            // (see `ClassSummary::confidence`) — a heuristics-only bucket
            // must not read as confidently as a labeled or trailer-based
            // one. Kept as evidence, not as a finding-level truth scale.
            "classification_confidence": classification_confidence,
            "caveat": PROVENANCE_CAVEAT,
        })),
        caused_by: Vec::new(),
        causes: Vec::new(),
    }
}

/// Classifies every commit in `commits`, applying label → trailer/marker →
/// heuristic precedence (see todo.md §3.G G6). Labels are checked first
/// since they're the confirmed-precise signal; heuristics only run for
/// commits no label or trailer/marker covers.
pub fn classify_commits(
    commits: &[CommitInfo],
    labels: &[ProvenanceLabel],
) -> HashMap<String, Classification> {
    let size_threshold = commit_size_threshold(commits);
    let low_cv_authors = authors_with_low_interval_cv(commits);

    commits
        .iter()
        .map(|commit| {
            let classification = match_label(commit, labels)
                .map(|label| {
                    let evidence = serde_json::json!({
                        "basis": "configured_label",
                        "evidence_class": "bounded_semantic",
                        "label": label.name,
                        "caveat": PROVENANCE_CAVEAT,
                    });
                    (
                        AuthorClass::Labeled(label.name.clone()),
                        LABEL_CONFIDENCE,
                        evidence,
                    )
                })
                .or_else(|| classify_trailer_or_marker(commit))
                .or_else(|| classify_heuristic(commit, size_threshold, &low_cv_authors))
                .unwrap_or_else(|| {
                    (
                        AuthorClass::Unknown,
                        0.0,
                        serde_json::json!({
                            "basis": "none",
                            "evidence_class": "heuristic",
                            "caveat": PROVENANCE_CAVEAT,
                        }),
                    )
                });
            (commit.id.clone(), classification)
        })
        .collect()
}

/// The first configured label whose `trailer_contains`/`author_email_contains`
/// needles match `commit` — labels win outright over heuristic
/// classification (see todo.md §3.G G6, "Labels sind das präzisere
/// Signal").
fn match_label<'a>(
    commit: &CommitInfo,
    labels: &'a [ProvenanceLabel],
) -> Option<&'a ProvenanceLabel> {
    labels.iter().find(|label| {
        let trailer_hit = label.trailer_contains.iter().any(|needle| {
            let needle = needle.to_lowercase();
            commit
                .trailers
                .iter()
                .any(|(_, value)| value.to_lowercase().contains(&needle))
        });
        let email_hit = label.author_email_contains.iter().any(|needle| {
            commit
                .author_email
                .to_lowercase()
                .contains(&needle.to_lowercase())
        });
        trailer_hit || email_hit
    })
}

/// Trailer/marker classification (see todo.md §3.G G6): a `Co-authored-by`
/// trailer naming a known agent, or Claude Code's `Generated with [...]`
/// commit-footer marker (free body text, not a git trailer). Checked in
/// order, most specific first.
fn classify_trailer_or_marker(commit: &CommitInfo) -> Option<Classification> {
    for (token, value) in &commit.trailers {
        if !token.eq_ignore_ascii_case("co-authored-by") {
            continue;
        }
        let lower = value.to_lowercase();
        let class = if lower.contains("claude") {
            AuthorClass::Agent("claude".to_string())
        } else if lower.contains("copilot") {
            AuthorClass::Agent("copilot".to_string())
        } else if lower.contains("cursor") {
            AuthorClass::Agent("cursor".to_string())
        } else if lower.contains("bot") || lower.contains("ai-assistant") {
            AuthorClass::Agent("bot".to_string())
        } else {
            continue;
        };
        return Some((class, TRAILER_CONFIDENCE, trailer_or_marker_evidence()));
    }

    for line in commit
        .message_title
        .lines()
        .chain(commit.message_body.lines())
    {
        let lower = line.to_lowercase();
        if !lower.contains("generated with [") {
            continue;
        }
        let class = if lower.contains("claude") {
            AuthorClass::Agent("claude".to_string())
        } else {
            AuthorClass::Agent("bot".to_string())
        };
        return Some((class, TRAILER_CONFIDENCE, trailer_or_marker_evidence()));
    }

    None
}

fn trailer_or_marker_evidence() -> serde_json::Value {
    serde_json::json!({
        "basis": "trailer_or_marker",
        "evidence_class": "heuristic",
        "trailer_present": true,
        "caveat": PROVENANCE_CAVEAT,
    })
}

/// Weakest tier: commit-size, time-distribution, and message-style
/// heuristics (see todo.md §3.G G6). Only reached when no label or
/// trailer/marker matched. Fires `AuthorClass::Agent("bot")` at low
/// confidence if any signal hits — heuristics alone can't name a specific
/// tool.
fn classify_heuristic(
    commit: &CommitInfo,
    size_threshold: Option<f64>,
    low_cv_authors: &HashSet<String>,
) -> Option<Classification> {
    let mut signals = Vec::new();

    if let Some(threshold) = size_threshold
        && commit.files_changed.len() as f64 > threshold
    {
        signals.push("commit_size_outlier");
    }
    if low_cv_authors.contains(&commit.author_email) {
        signals.push("time_distribution_anomaly");
    }
    if message_style_hit(&commit.message_title) || message_style_hit(&commit.message_body) {
        signals.push("message_style");
    }

    if signals.is_empty() {
        return None;
    }

    let evidence = serde_json::json!({
        "basis": "heuristic",
        "evidence_class": "heuristic",
        "signals": signals,
        "caveat": PROVENANCE_CAVEAT,
    });
    Some((
        AuthorClass::Agent("bot".to_string()),
        HEURISTIC_CONFIDENCE,
        evidence,
    ))
}

/// Whether `text` contains a phrase from `slop_text`'s existing
/// `conversational-artifact` tier lists (see todo.md §3.G G3) — reused
/// as-is rather than duplicated, matched here as plain lowercase-contains
/// with no position gating: a commit message is short enough that
/// Tier 2's "first 8 words" mitigation (built for code comments) isn't
/// needed.
fn message_style_hit(text: &str) -> bool {
    let lower = text.to_lowercase();
    crate::slop_text::CONVERSATIONAL_TIER1
        .iter()
        .chain(crate::slop_text::CONVERSATIONAL_TIER2.iter())
        .any(|phrase| lower.contains(phrase))
}

/// `mean + 2*stddev` of in-window commits' `files_changed` count, or `None`
/// if fewer than [`MIN_COMMITS_FOR_SIZE_OUTLIER`] commits are in-window
/// (small-sample honesty).
fn commit_size_threshold(commits: &[CommitInfo]) -> Option<f64> {
    if commits.len() < MIN_COMMITS_FOR_SIZE_OUTLIER {
        return None;
    }
    let sizes: Vec<f64> = commits
        .iter()
        .map(|commit| commit.files_changed.len() as f64)
        .collect();
    let (mean, stddev) = mean_and_stddev(&sizes);
    Some(mean + SIZE_OUTLIER_STDDEV_MULTIPLIER * stddev)
}

/// Author emails whose in-window inter-commit-interval coefficient of
/// variation falls below [`INTERVAL_CV_THRESHOLD`] — a suspiciously
/// regular commit cadence. Only computed for authors with at least
/// [`MIN_COMMITS_FOR_INTERVAL_CV`] in-window commits.
fn authors_with_low_interval_cv(commits: &[CommitInfo]) -> HashSet<String> {
    let mut by_author: HashMap<&str, Vec<i64>> = HashMap::new();
    for commit in commits {
        by_author
            .entry(commit.author_email.as_str())
            .or_default()
            .push(commit.time);
    }

    let mut flagged = HashSet::new();
    for (author, mut times) in by_author {
        if times.len() < MIN_COMMITS_FOR_INTERVAL_CV {
            continue;
        }
        times.sort_unstable();
        let gaps: Vec<f64> = times
            .windows(2)
            .map(|pair| (pair[1] - pair[0]) as f64)
            .collect();
        let (mean, stddev) = mean_and_stddev(&gaps);
        if mean <= 0.0 {
            continue;
        }
        if stddev / mean < INTERVAL_CV_THRESHOLD {
            flagged.insert(author.to_string());
        }
    }
    flagged
}

/// Population mean and standard deviation of `values`. `(0.0, 0.0)` for an
/// empty slice.
fn mean_and_stddev(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / values.len() as f64;
    (mean, variance.sqrt())
}

/// Per-file `git blame` results, cached across lookups within one run — a
/// second, separate pass from `ownership.rs`'s (accepted duplicated cost,
/// same precedent as `run_dead_code`'s second `DeepContext` load; see
/// `ownership::analyze_workspace` for the blame call this mirrors).
struct BlameCache<'repo> {
    repo: &'repo gix::Repository,
    head_id: gix::ObjectId,
    outcomes: HashMap<PathBuf, Option<gix::blame::Outcome>>,
}

impl<'repo> BlameCache<'repo> {
    fn new(repo: &'repo gix::Repository, head_id: gix::ObjectId) -> Self {
        Self {
            repo,
            head_id,
            outcomes: HashMap::new(),
        }
    }

    /// The id of the commit that introduced `line` (1-based) of
    /// `relative_path`, or `None` if the file couldn't be blamed or the
    /// line falls outside every blamed hunk.
    fn commit_for_line(&mut self, relative_path: &Path, line: usize) -> Option<String> {
        let repo = self.repo;
        let head_id = self.head_id;
        let outcome = self
            .outcomes
            .entry(relative_path.to_path_buf())
            .or_insert_with(|| {
                let relative_str = relative_path.to_string_lossy();
                let file_path: &BStr = BStr::new(relative_str.as_bytes());
                repo.blame_file(
                    file_path,
                    head_id,
                    gix::repository::blame_file::Options {
                        // Without this, gix does not follow a `git mv` rename
                        // at all (see `gix_blame`'s
                        // `tree_diff_without_rewrites_at_file_path`): a pure
                        // rename with no content change is treated as an
                        // `Addition`, so blame stops at the rename commit and
                        // misattributes every pre-rename line to whoever ran
                        // `git mv`, instead of the line's actual author.
                        // Plain `git blame` follows renames of the blamed
                        // file by default (no `--follow` needed — that flag
                        // is for `git log`), so this matches that default
                        // rather than introducing new behavior. Same fix as
                        // `ownership.rs`'s `blame_file` call.
                        rewrites: Some(gix::diff::Rewrites::default()),
                        ..Default::default()
                    },
                )
                .ok()
            });
        let outcome = outcome.as_ref()?;
        let zero_based = line.saturating_sub(1);
        outcome
            .entries
            .iter()
            .find(|entry| entry.range_in_blamed_file().contains(&zero_based))
            .map(|entry| entry.commit_id.to_string())
    }
}

/// Churn (files touched) tallied by the touching commit's author class (see
/// todo.md §3.G G6) — no blame needed, directly aggregated from
/// [`CommitInfo::files_changed`], mirroring `git::churn`'s counting-loop
/// shape but keyed by class instead of by file.
pub fn churn_by_class(
    commits: &[CommitInfo],
    classes: &HashMap<String, Classification>,
) -> HashMap<AuthorClass, u32> {
    let mut counts: HashMap<AuthorClass, u32> = HashMap::new();
    for commit in commits {
        let Some((class, _, _)) = classes.get(&commit.id) else {
            continue;
        };
        *counts.entry(class.clone()).or_insert(0) += commit.files_changed.len() as u32;
    }
    counts
}

/// Duplication-rate tallied by the author class of the commit that last
/// blamed each clone member's starting line (see todo.md §3.G G6).
pub fn duplication_rate_by_class(
    families: &[CloneFamily],
    workspace_root: &Path,
    classes: &HashMap<String, Classification>,
) -> Result<HashMap<AuthorClass, u32>, GitError> {
    let repo = gix::open(workspace_root)?;
    let Ok(head_id) = repo.head_id() else {
        return Ok(HashMap::new());
    };
    let mut blame = BlameCache::new(&repo, head_id.detach());

    let mut counts: HashMap<AuthorClass, u32> = HashMap::new();
    for family in families {
        for member in &family.members {
            let Ok(relative) = member.file.strip_prefix(workspace_root) else {
                continue;
            };
            let Some(commit_id) = blame.commit_for_line(relative, member.start_line) else {
                continue;
            };
            let Some((class, _, _)) = classes.get(&commit_id) else {
                continue;
            };
            *counts.entry(class.clone()).or_insert(0) += 1;
        }
    }
    Ok(counts)
}

/// `suppression-debt` findings tallied by the author class of the commit
/// that last blamed each finding's location (see todo.md §3.G G6).
pub fn suppression_debt_by_class(
    suppression_findings: &[Finding],
    workspace_root: &Path,
    classes: &HashMap<String, Classification>,
) -> Result<HashMap<AuthorClass, u32>, GitError> {
    let repo = gix::open(workspace_root)?;
    let Ok(head_id) = repo.head_id() else {
        return Ok(HashMap::new());
    };
    let mut blame = BlameCache::new(&repo, head_id.detach());

    let mut counts: HashMap<AuthorClass, u32> = HashMap::new();
    for finding in suppression_findings {
        let Ok(relative) = finding.location.file.strip_prefix(workspace_root) else {
            continue;
        };
        let Some(commit_id) = blame.commit_for_line(relative, finding.location.line.get()) else {
            continue;
        };
        let Some((class, _, _)) = classes.get(&commit_id) else {
            continue;
        };
        *counts.entry(class.clone()).or_insert(0) += 1;
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::duplication::DupeMode;
    use crate::ingest::{CrateInfo, SourceFile, SourceKind};
    use crate::test_util::TempDir;

    fn commit_info(id: &str, author_email: &str, time: i64) -> CommitInfo {
        CommitInfo {
            id: id.to_string(),
            author_email: author_email.to_string(),
            time,
            trailers: Vec::new(),
            message_title: "an ordinary commit".to_string(),
            message_body: String::new(),
            files_changed: vec![PathBuf::from("a.rs")],
        }
    }

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

    fn commit_sha(dir: &Path, rev: &str) -> String {
        let output = std::process::Command::new("git")
            .args(["rev-parse", rev])
            .current_dir(dir)
            .output()
            .expect("failed to run git rev-parse");
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_string()
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
    fn claude_co_authored_by_trailer_classifies_as_agent_claude() {
        let mut commit = commit_info("c1", "someone@example.com", 1_000);
        commit.trailers = vec![(
            "Co-authored-by".to_string(),
            "Claude <noreply@anthropic.com>".to_string(),
        )];

        let classes = classify_commits(&[commit], &[]);
        let (class, confidence, _) = &classes["c1"];
        assert_eq!(*class, AuthorClass::Agent("claude".to_string()));
        assert_eq!(*confidence, 0.85);
    }

    #[test]
    fn copilot_co_authored_by_trailer_classifies_as_agent_copilot() {
        let mut commit = commit_info("c1", "someone@example.com", 1_000);
        commit.trailers = vec![(
            "Co-authored-by".to_string(),
            "GitHub Copilot <copilot@github.com>".to_string(),
        )];

        let classes = classify_commits(&[commit], &[]);
        let (class, confidence, _) = &classes["c1"];
        assert_eq!(*class, AuthorClass::Agent("copilot".to_string()));
        assert_eq!(*confidence, 0.85);
    }

    #[test]
    fn cursor_co_authored_by_trailer_classifies_as_agent_cursor() {
        let mut commit = commit_info("c1", "someone@example.com", 1_000);
        commit.trailers = vec![(
            "Co-authored-by".to_string(),
            "Cursor <cursor@cursor.sh>".to_string(),
        )];

        let classes = classify_commits(&[commit], &[]);
        let (class, confidence, _) = &classes["c1"];
        assert_eq!(*class, AuthorClass::Agent("cursor".to_string()));
        assert_eq!(*confidence, 0.85);
    }

    #[test]
    fn generic_bot_trailer_classifies_as_agent_bot() {
        let mut commit = commit_info("c1", "someone@example.com", 1_000);
        commit.trailers = vec![(
            "Co-authored-by".to_string(),
            "ai-assistant <bot@example.com>".to_string(),
        )];

        let classes = classify_commits(&[commit], &[]);
        let (class, confidence, _) = &classes["c1"];
        assert_eq!(*class, AuthorClass::Agent("bot".to_string()));
        assert_eq!(*confidence, 0.85);
    }

    #[test]
    fn generated_with_claude_code_body_marker_classifies_as_agent_claude() {
        let mut commit = commit_info("c1", "someone@example.com", 1_000);
        commit.message_body = "🤖 Generated with [Claude Code](https://claude.ai/code)".to_string();

        let classes = classify_commits(&[commit], &[]);
        let (class, confidence, _) = &classes["c1"];
        assert_eq!(*class, AuthorClass::Agent("claude".to_string()));
        assert_eq!(*confidence, 0.85);
    }

    #[test]
    fn heuristic_only_commit_classifies_as_agent_bot_at_low_confidence() {
        // 11 ordinary, small, one-file commits establish the mean/stddev
        // baseline (>= MIN_COMMITS_FOR_SIZE_OUTLIER), then one outlier
        // touches far more files and carries a Tier 1 conversational
        // phrase, with no trailer/marker/label.
        let mut commits: Vec<CommitInfo> = (0..11)
            .map(|i| commit_info(&format!("normal-{i}"), "author@example.com", 1_000 + i))
            .collect();

        let mut outlier = commit_info("outlier", "author@example.com", 2_000);
        outlier.files_changed = (0..20).map(|i| PathBuf::from(format!("f{i}.rs"))).collect();
        outlier.message_body = "As an AI language model, I did this.".to_string();
        commits.push(outlier);

        let classes = classify_commits(&commits, &[]);
        let (class, confidence, evidence) = &classes["outlier"];
        assert_eq!(*class, AuthorClass::Agent("bot".to_string()));
        assert_eq!(*confidence, 0.35);
        let signals = evidence["signals"].as_array().unwrap();
        assert!(signals.iter().any(|s| s == "commit_size_outlier"));
        assert!(signals.iter().any(|s| s == "message_style"));
    }

    #[test]
    fn ordinary_commit_is_unknown_not_human() {
        let commit = commit_info("c1", "someone@example.com", 1_000);

        let classes = classify_commits(&[commit], &[]);
        let (class, _, _) = &classes["c1"];
        // There is no `AuthorClass::Human` variant — the type system itself
        // makes "absence of signal proves human authorship" impossible to
        // express.
        assert_eq!(*class, AuthorClass::Unknown);
    }

    #[test]
    fn configured_label_overrides_trailer_heuristic() {
        let mut commit = commit_info("c1", "contractor@example.com", 1_000);
        commit.trailers = vec![(
            "Co-authored-by".to_string(),
            "Claude <noreply@anthropic.com>".to_string(),
        )];
        let label = ProvenanceLabel {
            name: "contractor-x".to_string(),
            trailer_contains: Vec::new(),
            author_email_contains: vec!["contractor@example.com".to_string()],
        };

        let classes = classify_commits(&[commit], &[label]);
        let (class, confidence, _) = &classes["c1"];
        assert_eq!(*class, AuthorClass::Labeled("contractor-x".to_string()));
        assert_eq!(*confidence, 0.95);
    }

    #[test]
    fn trailer_wins_outright_over_conflicting_heuristic_signals() {
        // `classify_commits` chains `match_label(...).or_else(classify_trailer_or_marker)
        // .or_else(classify_heuristic)` — `Option::or_else` never evaluates a
        // later closure once an earlier one returned `Some`. So a commit
        // with BOTH a `Co-authored-by: Claude` trailer AND heuristic signals
        // that would independently qualify it as an outlier (a large
        // files-changed count, a Tier-1 "AI language model" phrase) is
        // classified purely from the trailer: `classify_heuristic` is never
        // even invoked for it, so the conflicting evidence is not merged,
        // averaged, or recorded anywhere — the trailer wins outright and the
        // heuristic signals leave no trace in the evidence.
        let mut commits: Vec<CommitInfo> = (0..11)
            .map(|i| commit_info(&format!("normal-{i}"), "author@example.com", 1_000 + i))
            .collect();

        let mut conflicted = commit_info("conflicted", "author@example.com", 2_000);
        conflicted.trailers = vec![(
            "Co-authored-by".to_string(),
            "Claude <noreply@anthropic.com>".to_string(),
        )];
        conflicted.files_changed = (0..20).map(|i| PathBuf::from(format!("f{i}.rs"))).collect();
        conflicted.message_body = "As an AI language model, I did this.".to_string();
        commits.push(conflicted);

        let classes = classify_commits(&commits, &[]);
        let (class, confidence, evidence) = &classes["conflicted"];

        assert_eq!(*class, AuthorClass::Agent("claude".to_string()));
        assert_eq!(*confidence, TRAILER_CONFIDENCE);
        assert_eq!(evidence["basis"], "trailer_or_marker");
        assert!(
            evidence.get("signals").is_none(),
            "heuristic signals must not appear in the evidence once a trailer matched: {evidence:?}"
        );
    }

    #[test]
    fn configured_label_wins_over_a_contradicting_trailer_in_the_full_pipeline() {
        // Complements `configured_label_overrides_trailer_heuristic` (which
        // exercises `classify_commits` directly with a synthetic
        // `CommitInfo`) with a real git fixture through the full
        // `analyze_workspace` pipeline: a commit carries a real
        // `Co-authored-by: Claude` trailer (parsed by `git::walk_commits`,
        // not hand-constructed), but a `[[provenance_label]]` also matches
        // it via `author_email_contains`. The label wins outright — the
        // commit's churn is attributed to `labeled-trusted-human`, not
        // `agent-claude`.
        let dir = TempDir::new("provenance-label-vs-trailer");
        git(&dir, &["init", "-q", "-b", "main"]);
        let file = dir.join("a.rs");
        std::fs::write(&file, "fn a() {}\n").unwrap();
        git(&dir, &["add", "."]);
        run_git(
            &dir,
            &[
                "-c",
                "user.email=trusted-human@example.com",
                "commit",
                "-q",
                "-m",
                "add a\n\nCo-authored-by: Claude <noreply@anthropic.com>",
            ],
            &[],
        );

        let workspace = workspace_of(dir.to_path_buf(), file);
        let label = ProvenanceLabel {
            name: "trusted-human".to_string(),
            trailer_contains: Vec::new(),
            author_email_contains: vec!["trusted-human@example.com".to_string()],
        };
        let breakdown = analyze_workspace(&workspace, 30, &[label]);

        assert!(breakdown.errors.is_empty(), "{:?}", breakdown.errors);
        assert!(
            breakdown
                .findings
                .iter()
                .any(|f| f.id.as_str().ends_with("labeled-trusted-human")),
            "the labeled class must win: {:?}",
            breakdown.findings
        );
        assert!(
            breakdown
                .findings
                .iter()
                .all(|f| !f.id.as_str().ends_with("agent-claude")),
            "the contradicting Claude trailer must not surface as a class despite \
             being present in the commit: {:?}",
            breakdown.findings
        );
    }

    #[test]
    fn a_repos_first_commit_with_no_history_is_unknown_not_misclassified() {
        // The size-outlier and interval-CV heuristics both require a
        // baseline sample (`MIN_COMMITS_FOR_SIZE_OUTLIER` = 10,
        // `MIN_COMMITS_FOR_INTERVAL_CV` = 5) before they run at all — a
        // repo's very first commit has no comparison basis for "unusual"
        // file count or cadence. This documents that a first commit
        // touching many files, with an ordinary message and no trailer, is
        // NOT flagged as an outlier just because there's no history to
        // compare it against: it lands in `Unknown`, not in any `agent-*`
        // bucket.
        let dir = TempDir::new("provenance-first-commit-no-history");
        git(&dir, &["init", "-q", "-b", "main"]);
        for i in 0..15 {
            std::fs::write(dir.join(format!("f{i}.rs")), format!("fn f{i}() {{}}\n")).unwrap();
        }
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial import"]);

        let workspace = workspace_of(dir.to_path_buf(), dir.join("f0.rs"));
        let breakdown = analyze_workspace(&workspace, 30, &[]);

        assert!(breakdown.errors.is_empty(), "{:?}", breakdown.errors);
        assert!(
            breakdown
                .findings
                .iter()
                .any(|f| f.rule == PROVENANCE_CHURN_RULE && f.id.as_str().ends_with("unknown")),
            "the first commit must classify as unknown: {:?}",
            breakdown.findings
        );
        assert!(
            breakdown
                .findings
                .iter()
                .all(|f| !f.id.as_str().contains("agent-")),
            "no agent-* class may appear without any evidence: {:?}",
            breakdown.findings
        );
    }

    #[test]
    fn analyze_workspace_excludes_commits_outside_the_window() {
        let dir = TempDir::new("provenance-window");
        git(&dir, &["init", "-q", "-b", "main"]);

        let old_date = [
            ("GIT_AUTHOR_DATE", "2000-01-01T00:00:00"),
            ("GIT_COMMITTER_DATE", "2000-01-01T00:00:00"),
        ];
        let file = dir.join("old.rs");
        std::fs::write(&file, "fn old() {}\n").unwrap();
        run_git(&dir, &["add", "."], &[]);
        run_git(&dir, &["commit", "-q", "-m", "ancient"], &old_date);

        std::fs::write(dir.join("new.rs"), "fn new() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "recent"]);

        let workspace = workspace_of(dir.to_path_buf(), file);
        let breakdown = analyze_workspace(&workspace, 30, &[]);

        assert!(breakdown.errors.is_empty(), "{:?}", breakdown.errors);
        let total_churn: u32 = breakdown.by_class.iter().map(|s| s.churn).sum();
        // Only the "recent" commit (1 file) is in-window.
        assert_eq!(total_churn, 1);
    }

    #[test]
    fn aggregate_finding_evidence_reflects_the_classification_not_a_hardcoded_one() {
        // A trailer-based classification (0.85) must not be reported as if
        // it were certain just because the resulting *count* is exact —
        // the finding stays `heuristic`, and the classification confidence
        // survives as evidence (see `ClassSummary::confidence`'s doc
        // comment).
        let dir = TempDir::new("provenance-confidence");
        git(&dir, &["init", "-q", "-b", "main"]);
        let file = dir.join("a.rs");
        std::fs::write(&file, "fn a() {}\n").unwrap();
        git(&dir, &["add", "."]);
        run_git(
            &dir,
            &[
                "commit",
                "-q",
                "-m",
                "add a\n\nCo-authored-by: Claude <noreply@anthropic.com>",
            ],
            &[],
        );

        let workspace = workspace_of(dir.to_path_buf(), file);
        let breakdown = analyze_workspace(&workspace, 30, &[]);

        assert!(breakdown.errors.is_empty(), "{:?}", breakdown.errors);
        let claude_churn = breakdown
            .findings
            .iter()
            .find(|f| f.rule == PROVENANCE_CHURN_RULE && f.id.as_str().ends_with("agent-claude"))
            .expect("a Claude-trailer commit must produce a churn-by-class finding");
        assert_eq!(claude_churn.evidence_class, EvidenceClass::Heuristic);
        let evidence = claude_churn.evidence.as_ref().unwrap();
        let classification_confidence =
            evidence["classification_confidence"].as_f64().unwrap() as f32;
        assert_eq!(classification_confidence, 0.85);
    }

    #[test]
    fn churn_by_class_tallies_files_changed_per_class() {
        let mut commit = commit_info("c1", "someone@example.com", 1_000);
        commit.files_changed = vec![PathBuf::from("a.rs"), PathBuf::from("b.rs")];
        commit.trailers = vec![(
            "Co-authored-by".to_string(),
            "Claude <noreply@anthropic.com>".to_string(),
        )];

        let classes = classify_commits(std::slice::from_ref(&commit), &[]);
        let counts = churn_by_class(&[commit], &classes);

        assert_eq!(
            counts.get(&AuthorClass::Agent("claude".to_string())),
            Some(&2)
        );
    }

    fn clone_member(file: PathBuf, start_line: usize) -> crate::duplication::CloneMember {
        crate::duplication::CloneMember {
            qualified_name: "f".to_string(),
            file,
            start_line,
            end_line: start_line,
            start_token: 0,
            end_token: 10,
            token_count: 11,
            mode: DupeMode::Mild,
            identifier_mapping: Vec::new(),
            normalized_literal_kinds: Vec::new(),
        }
    }

    #[test]
    fn duplication_rate_by_class_blames_the_span_to_its_class() {
        let dir = TempDir::new("provenance-dupe-blame");
        git(&dir, &["init", "-q", "-b", "main"]);

        let file = dir.join("a.rs");
        std::fs::write(&file, "fn a() {}\n").unwrap();
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
        let sha = commit_sha(&dir, "HEAD");

        let classes = HashMap::from([(
            sha,
            (
                AuthorClass::Agent("claude".to_string()),
                0.85,
                serde_json::json!({}),
            ),
        )]);
        let family = CloneFamily {
            members: vec![clone_member(file, 1)],
        };

        let counts = duplication_rate_by_class(&[family], &dir, &classes).unwrap();

        assert_eq!(
            counts.get(&AuthorClass::Agent("claude".to_string())),
            Some(&1)
        );
    }

    #[test]
    fn suppression_debt_by_class_blames_the_finding_to_its_class() {
        let dir = TempDir::new("provenance-suppression-blame");
        git(&dir, &["init", "-q", "-b", "main"]);

        let file = dir.join("a.rs");
        std::fs::write(&file, "#[allow(dead_code)]\nfn a() {}\n").unwrap();
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
        let sha = commit_sha(&dir, "HEAD");

        let classes = HashMap::from([(
            sha,
            (
                AuthorClass::Agent("claude".to_string()),
                0.85,
                serde_json::json!({}),
            ),
        )]);
        let finding = Finding {
            id: "suppression-debt:dead_code".into(),
            rule: crate::slop::SUPPRESSION_DEBT_RULE.into(),
            severity: Severity::Info,
            location: Location {
                file: file.clone(),
                line: OneBasedLine::FIRST,
                item_path: "dead_code".to_string(),
            },
            evidence_class: EvidenceClass::DerivedFact,
            origin: Origin::Code,
            evidence: None,
            caused_by: Vec::new(),
            causes: Vec::new(),
        };

        let counts = suppression_debt_by_class(&[finding], &dir, &classes).unwrap();

        assert_eq!(
            counts.get(&AuthorClass::Agent("claude".to_string())),
            Some(&1)
        );
    }

    #[test]
    fn provenance_error_source_preserves_the_wrapped_domain_error() {
        let err = ProvenanceError::Git(GitError::InvalidWindow(0));
        let source = std::error::Error::source(&err).expect("Git must carry a source");
        assert!(source.downcast_ref::<GitError>().is_some());
    }
}
