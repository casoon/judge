//! Coverage import from `cargo-llvm-cov`'s LCOV output (see todo.md §J).
//! judge never measures coverage itself — it only reads an already-generated
//! snapshot, so every coverage-derived claim is `external_measurement`
//! evidence (todo.md §17.2/§17.3), never something judge derived on its own.
//!
//! Two things live here: a minimal LCOV line-coverage parser
//! ([`parse_lcov`]/[`read_lcov`]), and `untested-hotspot`
//! ([`untested_hotspots`]) — the intersection of high complexity, high
//! churn, and mostly-uncovered lines that todo.md §J calls out as "die Zahl,
//! die eine Priorisierung erlaubt".

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::json;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::complexity::FunctionInfo;
use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};
use crate::ingest::Workspace;

/// Rule id for [`untested_hotspots`] (see todo.md §J).
pub const UNTESTED_HOTSPOT_RULE: &str = "untested-hotspot";
/// Bump when the untested-hotspot rule's logic changes (see todo.md §5
/// "Regelversions-Schutz").
pub const UNTESTED_HOTSPOT_RULE_REVISION: u32 = 1;

/// The churn window [`untested_hotspots`] expects its `churn` argument to
/// have been computed with. Reuses `crate::slop_structural`'s
/// `churn-hotspot` window (and, internally, its threshold) so the two rules
/// don't silently disagree on what "high churn" means for the same
/// workspace (see todo.md §J, §3.G).
pub const UNTESTED_HOTSPOT_CHURN_WINDOW_DAYS: i64 =
    crate::slop_structural::CHURN_HOTSPOT_WINDOW_DAYS;

/// Minimum cyclomatic complexity for a function to count as "high
/// complexity" for `untested-hotspot` purposes — the conventional McCabe
/// "high complexity" cutoff used across static-analysis tooling. No existing
/// judge threshold covers per-function complexity in isolation;
/// `crate::slop_structural`'s `complexity-inflation` looks the other way
/// (implausibly *low* complexity for a function's size).
pub const HIGH_COMPLEXITY_THRESHOLD: u32 = 10;

/// Minimum share of a function's lines that must be uncovered for it to
/// count as "mostly untested" (todo.md §J: "niedrige Coverage").
const UNCOVERED_MAJORITY_RATIO: f64 = 0.5;

/// Line coverage for a single source file, parsed from LCOV `DA:` records.
/// Function/branch coverage (`FN:`/`FNDA:`/`BRDA:`) is out of scope — see
/// [`parse_lcov`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileCoverage {
    pub lines_total: usize,
    pub lines_covered: usize,
    /// Sorted, deduplicated line numbers with zero hits.
    pub uncovered_lines: Vec<usize>,
}

impl FileCoverage {
    /// Share of instrumented lines with at least one hit, as a percentage.
    /// `None` for a file LCOV lists with zero instrumented lines — there is
    /// nothing to divide by, and reporting `0%`/`100%` either way would be a
    /// fabricated claim.
    pub fn covered_pct(&self) -> Option<f64> {
        if self.lines_total == 0 {
            None
        } else {
            Some(self.lines_covered as f64 / self.lines_total as f64 * 100.0)
        }
    }
}

/// Parsed LCOV per-file line coverage, plus files LCOV reported that no
/// longer exist in the workspace (see todo.md §J: renamed/deleted since the
/// coverage run — collected here, never silently dropped and never read as
/// 0% coverage).
#[derive(Debug, Clone, Default)]
pub struct CoverageReport {
    /// Keyed by path relative to the workspace root when an `SF:` entry
    /// resolves under it (matching `crate::git::churn`'s convention for its
    /// own keys); kept in its original (typically absolute) form otherwise,
    /// so a relative-path lookup for a workspace file deliberately misses
    /// rather than accidentally matching an unrelated absolute path.
    pub per_file: HashMap<PathBuf, FileCoverage>,
    /// LCOV-declared `SF:` paths that don't exist on disk (checked relative
    /// to the workspace root, or as given if already absolute).
    pub missing_files: Vec<PathBuf>,
}

impl CoverageReport {
    /// Coverage for a workspace source file, looked up the same way
    /// [`crate::git::hotspots`] matches complexity to churn: `file` is an
    /// absolute path (as `FunctionInfo::file`/`crate::ingest::SourceFile`
    /// paths are), stripped of `workspace_root` before the lookup. `None`
    /// means "no coverage data for this file" — a state distinct from 0%
    /// covered (todo.md §J).
    pub fn for_file(&self, workspace_root: &Path, file: &Path) -> Option<&FileCoverage> {
        let relative = file.strip_prefix(workspace_root).unwrap_or(file);
        self.per_file.get(relative)
    }

    /// Workspace source files (absolute paths, as `for_file` expects) with
    /// no matching LCOV entry at all. Never asserted to be 0% covered —
    /// "no coverage data" is its own state (todo.md §J).
    pub fn files_without_coverage_data<'a>(
        &self,
        workspace_root: &Path,
        files: impl IntoIterator<Item = &'a Path>,
    ) -> Vec<PathBuf> {
        let mut missing: Vec<PathBuf> = files
            .into_iter()
            .filter(|file| self.for_file(workspace_root, file).is_none())
            .map(Path::to_path_buf)
            .collect();
        missing.sort();
        missing
    }
}

/// Failure reading an LCOV file from disk (see [`read_lcov`]). Parsing its
/// contents never fails — malformed records are skipped, see [`parse_lcov`].
#[derive(Debug)]
pub struct LcovError {
    path: PathBuf,
    source: std::io::Error,
}

impl std::fmt::Display for LcovError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: failed to read LCOV report: {}",
            self.path.display(),
            self.source
        )
    }
}

impl std::error::Error for LcovError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Reads and parses an LCOV report from `path` (see [`parse_lcov`]).
pub fn read_lcov(path: &Path, workspace_root: &Path) -> Result<CoverageReport, LcovError> {
    let text = std::fs::read_to_string(path).map_err(|source| LcovError {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(parse_lcov(&text, workspace_root))
}

/// Minimal LCOV parser: recognizes `SF:<path>`, `DA:<line>,<hits>[,...]`,
/// and `end_of_record`; every other record (`FN:`/`FNDA:`/`BRDA:`/…) is
/// ignored — function/branch coverage is out of scope, only line coverage
/// (see todo.md §J). Unparseable `DA:` lines are skipped rather than
/// failing the whole parse: a handful of unreadable records shouldn't
/// discard an otherwise-usable snapshot.
///
/// `SF:` paths are normalized relative to `workspace_root` when they are
/// absolute and resolve under it; already-relative paths have any `.`
/// (current-dir) components stripped — e.g. `./src/lib.rs` and `src/lib.rs`
/// resolve to the same key — since [`CoverageReport::for_file`] strips
/// `function.file` (always an absolute, `.`-free path) the same way and a
/// stray leading `./` would otherwise silently miss an existing entry (see
/// [`resolve_lcov_path`]). Case (on case-insensitive filesystems) is *not*
/// normalized — a `SF:` path differing only in case from the workspace path
/// still misses, since judge cannot know a given filesystem's case
/// sensitivity from its inputs alone. After parsing, every resulting path is
/// checked for existence and recorded in [`CoverageReport::missing_files`] if
/// it isn't found — see todo.md §J point 2.
pub fn parse_lcov(text: &str, workspace_root: &Path) -> CoverageReport {
    let mut per_file: HashMap<PathBuf, FileCoverage> = HashMap::new();
    let mut current: Option<(PathBuf, HashMap<usize, u64>)> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if let Some(raw_path) = line.strip_prefix("SF:") {
            if let Some((path, lines)) = current.take() {
                per_file.insert(path, finalize_file(lines));
            }
            let resolved = resolve_lcov_path(raw_path.trim(), workspace_root);
            current = Some((resolved, HashMap::new()));
        } else if let Some(rest) = line.strip_prefix("DA:") {
            if let Some((_, lines)) = current.as_mut()
                && let Some((line_no, hits)) = parse_da(rest)
            {
                lines.insert(line_no, hits);
            }
        } else if line == "end_of_record"
            && let Some((path, lines)) = current.take()
        {
            per_file.insert(path, finalize_file(lines));
        }
    }
    // A file section without a trailing `end_of_record` still counts — LCOV
    // requires it, but a truncated/malformed report shouldn't lose the last
    // file's data.
    if let Some((path, lines)) = current.take() {
        per_file.insert(path, finalize_file(lines));
    }

    let mut missing_files: Vec<PathBuf> = per_file
        .keys()
        .filter(|path| {
            let absolute = if path.is_absolute() {
                (*path).clone()
            } else {
                workspace_root.join(path)
            };
            !absolute.exists()
        })
        .cloned()
        .collect();
    missing_files.sort();

    CoverageReport {
        per_file,
        missing_files,
    }
}

fn resolve_lcov_path(raw_path: &str, workspace_root: &Path) -> PathBuf {
    let path = PathBuf::from(raw_path);
    if path.is_absolute() {
        path.strip_prefix(workspace_root)
            .map(Path::to_path_buf)
            .unwrap_or(path)
    } else {
        // Strip `.` components (e.g. a leading `./`) so `./src/lib.rs` keys
        // the same entry as `src/lib.rs` — `for_file` never produces a `.`
        // component when it strips an absolute `function.file`, so leaving
        // one in here would make an otherwise-matching file look like it has
        // no coverage data at all.
        path.components()
            .filter(|component| !matches!(component, std::path::Component::CurDir))
            .collect()
    }
}

fn parse_da(rest: &str) -> Option<(usize, u64)> {
    let mut parts = rest.split(',');
    let line = parts.next()?.trim().parse::<usize>().ok()?;
    let hits = parts.next()?.trim().parse::<u64>().ok()?;
    Some((line, hits))
}

fn finalize_file(lines: HashMap<usize, u64>) -> FileCoverage {
    let mut uncovered_lines: Vec<usize> = lines
        .iter()
        .filter(|&(_, &hits)| hits == 0)
        .map(|(&line, _)| line)
        .collect();
    uncovered_lines.sort_unstable();
    let lines_total = lines.len();
    let lines_covered = lines_total - uncovered_lines.len();
    FileCoverage {
        lines_total,
        lines_covered,
        uncovered_lines,
    }
}

/// Flags functions where high complexity, high recent file churn, and
/// mostly uncovered lines all coincide — the intersection todo.md §J calls
/// `untested-hotspot`: "hohe Komplexität, hoher Churn, niedrige Coverage".
///
/// `churn` must be computed over [`UNTESTED_HOTSPOT_CHURN_WINDOW_DAYS`] (the
/// same window `crate::slop_structural::churn_hotspots` uses) — this
/// function only reads it, it doesn't call `crate::git::churn` itself.
///
/// A function whose file has no coverage data at all is skipped, not
/// treated as uncovered (todo.md §J: "keine Coverage-Daten" is its own
/// state, not an unproven 0%-coverage claim).
///
/// Evidence class: [`EvidenceClass::ExternalMeasurement`]. Complexity alone
/// would be `derived_fact` and churn alone `heuristic`
/// (see `crate::finding::evidence_class_for_rule`'s doc table), but coverage
/// — an external snapshot judge can neither measure nor recompute itself —
/// is the rarest and least locally-verifiable ingredient in the
/// combination, so it sets the class for the combined claim (todo.md
/// §17.3).
///
/// Known, undecidable time skew: `churn` and `coverage` are read as of two
/// independent snapshots — `churn` from the workspace's current git history,
/// `coverage` from whenever the LCOV report was generated (a CI run that can
/// be days or weeks old). Both use the *current* function line ranges from
/// `functions`. If a hotspot was reworked after the LCOV snapshot was taken,
/// the reported `lines_covered_pct`/`uncovered_line_count` describe lines
/// that may no longer exist in their current form — judge has no way to
/// detect this from the LCOV file alone (it carries no commit/timestamp
/// judge could compare against `AnalysisUniverse`'s commit). This is a
/// structural limitation of importing an external snapshot, not a bug: it
/// cannot be fixed by adjusting `UNTESTED_HOTSPOT_CHURN_WINDOW_DAYS` or any
/// other local threshold.
pub fn untested_hotspots(
    functions: &[FunctionInfo],
    churn: &HashMap<PathBuf, u32>,
    coverage: &CoverageReport,
    workspace_root: &Path,
) -> Vec<Finding> {
    let mut findings: Vec<Finding> = functions
        .iter()
        .filter(|function| function.cyclomatic >= HIGH_COMPLEXITY_THRESHOLD)
        .filter_map(|function| {
            let relative_file = function.file.strip_prefix(workspace_root).ok()?;
            let file_churn = *churn.get(relative_file)?;
            if file_churn < crate::slop_structural::CHURN_HOTSPOT_THRESHOLD {
                return None;
            }
            let file_coverage = coverage.for_file(workspace_root, &function.file)?;

            let end_line = function.line + function.lines_of_code.saturating_sub(1);
            let uncovered_in_function = file_coverage
                .uncovered_lines
                .iter()
                .filter(|&&line| (function.line..=end_line).contains(&line))
                .count();
            let uncovered_ratio = uncovered_in_function as f64 / function.lines_of_code as f64;
            if uncovered_ratio <= UNCOVERED_MAJORITY_RATIO {
                return None;
            }

            Some(Finding {
                id: format!(
                    "{UNTESTED_HOTSPOT_RULE}:{}:{}",
                    function.file.display(),
                    function.qualified_name
                )
                .into(),
                rule: UNTESTED_HOTSPOT_RULE.into(),
                severity: Severity::Warn,
                location: Location {
                    file: function.file.clone(),
                    line: OneBasedLine::new(function.line)
                        .expect("proc-macro2 span lines are 1-based"),
                    item_path: function.qualified_name.clone(),
                },
                evidence_class: EvidenceClass::ExternalMeasurement,
                origin: Origin::Code,
                evidence: Some(json!({
                    "cyclomatic_complexity": function.cyclomatic,
                    "file_churn": file_churn,
                    "lines_covered_pct": file_coverage.covered_pct(),
                    "uncovered_line_count": uncovered_in_function,
                })),
                caused_by: Vec::new(),
                causes: Vec::new(),
            })
        })
        .collect();
    findings.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    findings
}

/// A crate's authored test-to-production LOC split (see todo.md §J
/// "Test-zu-Code-Ratio pro Crate, Verteilung"). A pure metric, not a
/// `Finding`: there is no universal "good" ratio to gate on — a pure
/// data-types crate can legitimately have zero tests, and a proc-macro
/// crate's real tests often live entirely in a separate integration-test
/// crate this per-crate LOC count cannot see. Any threshold here would
/// assert "undertested" as fact, which todo.md §5's wording rule forbids for
/// anything short of `derived_fact` evidence. Mirrors
/// `crate::complexity::FunctionInfo::cyclomatic`: a bare value other things
/// can read, never a standalone claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateTestRatio {
    pub crate_name: String,
    pub production_loc: u64,
    pub test_loc: u64,
}

impl CrateTestRatio {
    /// `test_loc / production_loc`, or `None` when `production_loc` is zero
    /// — nothing to divide by (mirrors [`FileCoverage::covered_pct`]'s
    /// no-fabricated-number precedent). A crate with `test_loc == 0` and
    /// nonzero `production_loc` yields `Some(0.0)`: "no tests" is a
    /// well-defined ratio, not a missing one.
    pub fn ratio(&self) -> Option<f64> {
        if self.production_loc == 0 {
            None
        } else {
            Some(self.test_loc as f64 / self.production_loc as f64)
        }
    }
}

/// Line spans (1-based, inclusive) of every `#[cfg(test)]`-attributed module
/// in a parsed file — adapts `crate::deps`'s `CfgTestIdentCollector` (which
/// collects identifiers referenced inside such a module) into a span
/// collector instead, reusing its exact `#[cfg(test)]` detection
/// (`crate::deps::attrs_have_cfg_test`) rather than re-parsing attributes
/// from scratch. Like `CfgTestIdentCollector`, doesn't descend into a
/// `#[cfg(test)]` module once found, so sibling/nested test modules never
/// double-count a line.
#[derive(Default)]
struct CfgTestModSpanCollector {
    spans: Vec<(usize, usize)>,
}

impl<'ast> Visit<'ast> for CfgTestModSpanCollector {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if crate::deps::attrs_have_cfg_test(&node.attrs) {
            let start_line = node.span().start().line;
            let end_line = node.span().end().line.max(start_line);
            self.spans.push((start_line, end_line));
        } else {
            visit::visit_item_mod(self, node);
        }
    }
}

/// Parses `path` and returns the line spans of its top-level `#[cfg(test)]`
/// modules (see [`CfgTestModSpanCollector`]). `None` if the file can't be
/// read or parsed — the caller then falls back to treating the whole file as
/// production code, matching how [`size_distribution`](crate::git::size_distribution)
/// and `crate::health_score::total_authored_loc` silently skip unreadable
/// files rather than failing outright.
fn cfg_test_mod_line_spans(path: &Path) -> Option<Vec<(usize, usize)>> {
    let source = std::fs::read_to_string(path).ok()?;
    let ast = syn::parse_file(&source).ok()?;
    let mut collector = CfgTestModSpanCollector::default();
    collector.visit_file(&ast);
    Some(collector.spans)
}

/// Computes [`CrateTestRatio`] for every crate in `workspace`, over its
/// [`crate::ingest::SourceKind::Authored`] files.
///
/// A file counts entirely towards `test_loc` if it sits under a `tests/`
/// directory — reusing `crate::deps::classify_domain`'s existing path
/// classification, which also groups `examples/`/`benches/` files into the
/// same `Dev` domain; those are counted as test LOC here too, rather than
/// re-deriving a narrower "`tests/` only" classifier (a deliberate reuse
/// choice, not an oversight — see this task's judgment-call note).
/// Otherwise, a `src/`-located file contributes to both counts if it
/// contains one or more `#[cfg(test)] mod ...` blocks: the lines inside
/// those blocks count as `test_loc`, the rest of the file as
/// `production_loc`. Everything else (including `build.rs`) counts entirely
/// as `production_loc`. An unreadable or unparseable file is skipped, not
/// treated as either.
pub fn test_ratios(workspace: &Workspace) -> Vec<CrateTestRatio> {
    workspace
        .crates
        .iter()
        .map(|krate| {
            let mut production_loc: u64 = 0;
            let mut test_loc: u64 = 0;

            for file in &krate.source_files {
                if !file.kind.is_locally_reportable() {
                    continue;
                }
                let Ok(content) = std::fs::read_to_string(&file.path) else {
                    continue;
                };
                let total_lines = content.lines().count() as u64;

                let relative = file
                    .path
                    .strip_prefix(&krate.root)
                    .unwrap_or(file.path.as_path());
                if crate::deps::classify_domain(relative) == crate::deps::UsageDomain::Dev {
                    test_loc += total_lines;
                    continue;
                }

                match cfg_test_mod_line_spans(&file.path) {
                    Some(spans) if !spans.is_empty() => {
                        let test_lines_in_file: u64 = spans
                            .iter()
                            .map(|&(start, end)| (end - start + 1) as u64)
                            .sum();
                        test_loc += test_lines_in_file;
                        production_loc += total_lines.saturating_sub(test_lines_in_file);
                    }
                    _ => production_loc += total_lines,
                }
            }

            CrateTestRatio {
                crate_name: krate.name.clone(),
                production_loc,
                test_loc,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    #[test]
    fn parse_lcov_computes_totals_and_uncovered_lines() {
        let dir = TempDir::new("coverage-parse-basic");
        std::fs::write(dir.join("lib.rs"), "fn a() {}\n").unwrap();

        let lcov = "\
SF:lib.rs
DA:1,3
DA:2,0
DA:3,0
DA:4,7
end_of_record
";
        let report = parse_lcov(lcov, &dir);

        let coverage = report.per_file.get(&PathBuf::from("lib.rs")).unwrap();
        assert_eq!(coverage.lines_total, 4);
        assert_eq!(coverage.lines_covered, 2);
        assert_eq!(coverage.uncovered_lines, vec![2, 3]);
        assert!(report.missing_files.is_empty());
    }

    #[test]
    fn parse_lcov_ignores_fn_fnda_and_brda_records() {
        let dir = TempDir::new("coverage-parse-ignored-records");
        std::fs::write(dir.join("lib.rs"), "fn a() {}\n").unwrap();

        let lcov = "\
SF:lib.rs
FN:1,a
FNDA:1,a
BRDA:1,0,0,1
DA:1,1
end_of_record
";
        let report = parse_lcov(lcov, &dir);

        let coverage = report.per_file.get(&PathBuf::from("lib.rs")).unwrap();
        assert_eq!(coverage.lines_total, 1);
        assert_eq!(coverage.lines_covered, 1);
    }

    #[test]
    fn parse_lcov_normalizes_absolute_paths_under_the_workspace_root() {
        let dir = TempDir::new("coverage-parse-absolute");
        std::fs::write(dir.join("lib.rs"), "fn a() {}\n").unwrap();

        let lcov = format!(
            "SF:{}\nDA:1,1\nend_of_record\n",
            dir.join("lib.rs").display()
        );
        let report = parse_lcov(&lcov, &dir);

        assert!(report.per_file.contains_key(&PathBuf::from("lib.rs")));
    }

    #[test]
    fn parse_lcov_reports_a_missing_file_without_crashing() {
        let dir = TempDir::new("coverage-parse-missing-file");
        // `renamed.rs` is never written to disk — simulates a file renamed
        // or deleted since the coverage run.
        let lcov = "\
SF:renamed.rs
DA:1,1
end_of_record
";
        let report = parse_lcov(lcov, &dir);

        assert_eq!(report.missing_files, vec![PathBuf::from("renamed.rs")]);
        // Still parsed — a stale entry is reported, not dropped.
        assert!(report.per_file.contains_key(&PathBuf::from("renamed.rs")));
    }

    #[test]
    fn parse_lcov_strips_a_leading_curdir_so_the_path_matches_the_workspace_relative_form() {
        // `cargo-llvm-cov`/`grcov` invocations can emit `SF:./src/lib.rs`
        // instead of `SF:src/lib.rs` depending on how they're run. Without
        // stripping the `./`, this key would never match `for_file`'s
        // lookup (which strips an absolute `function.file` down to
        // `src/lib.rs`, no `./`) — a real, silent false negative fixed
        // alongside this fixture (see `resolve_lcov_path`).
        let dir = TempDir::new("coverage-parse-leading-curdir");
        std::fs::write(dir.join("lib.rs"), "fn a() {}\n").unwrap();

        let lcov = "SF:./lib.rs\nDA:1,1\nend_of_record\n";
        let report = parse_lcov(lcov, &dir);

        assert!(report.per_file.contains_key(&PathBuf::from("lib.rs")));
        assert!(report.for_file(&dir, &dir.join("lib.rs")).is_some());
    }

    #[test]
    fn coverage_report_for_file_misses_when_lcov_case_differs_from_the_workspace_path() {
        // Same file, different case in the LCOV report — plausible when a
        // report is generated on one OS/tool invocation and consumed
        // locally, or the workspace filesystem is case-insensitive (macOS,
        // Windows) so `SRC/HOT.RS` and `src/hot.rs` name the same file on
        // disk. Documented, not fixed: judge cannot know a given
        // filesystem's case sensitivity from its inputs alone (see
        // `parse_lcov`'s doc comment), so this is expected to miss.
        let dir = TempDir::new("coverage-case-mismatch");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/hot.rs"), "fn hot() {}\n").unwrap();

        let lcov = "SF:SRC/HOT.RS\nDA:1,1\nend_of_record\n";
        let report = parse_lcov(lcov, &dir);

        assert!(report.for_file(&dir, &dir.join("src/hot.rs")).is_none());
    }

    #[test]
    fn read_lcov_errors_clearly_for_a_missing_report_file() {
        let dir = TempDir::new("coverage-read-missing-report");
        let err = read_lcov(&dir.join("nope.info"), &dir).unwrap_err();
        assert!(err.to_string().contains("nope.info"));
    }

    #[test]
    fn covered_pct_is_none_for_a_file_with_zero_instrumented_lines() {
        let coverage = FileCoverage::default();
        assert_eq!(coverage.covered_pct(), None);
    }

    #[test]
    fn covered_pct_computes_a_percentage() {
        let coverage = FileCoverage {
            lines_total: 4,
            lines_covered: 3,
            uncovered_lines: vec![2],
        };
        assert_eq!(coverage.covered_pct(), Some(75.0));
    }

    #[test]
    fn files_without_coverage_data_lists_workspace_files_absent_from_lcov() {
        let dir = TempDir::new("coverage-no-data");
        let mut report = CoverageReport::default();
        report.per_file.insert(
            PathBuf::from("src/covered.rs"),
            FileCoverage {
                lines_total: 1,
                lines_covered: 1,
                uncovered_lines: Vec::new(),
            },
        );

        let covered = dir.join("src/covered.rs");
        let uncovered = dir.join("src/untested.rs");
        let missing =
            report.files_without_coverage_data(&dir, [covered.as_path(), uncovered.as_path()]);

        assert_eq!(missing, vec![uncovered]);
    }

    fn git(dir: &Path, args: &[&str]) {
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
            .status()
            .expect("failed to run git — required for these fixtures");
        assert!(status.success(), "git {args:?} failed");
    }

    fn function_info(
        file: PathBuf,
        line: usize,
        cyclomatic: u32,
        lines_of_code: usize,
    ) -> FunctionInfo {
        FunctionInfo {
            qualified_name: "hot_fn".to_string(),
            file,
            line,
            cyclomatic,
            lines_of_code,
            nesting_depth: 0,
            match_arm_count: 0,
            arg_count: 0,
        }
    }

    /// End-to-end fixture in the style of `crate::git`'s `hotspots` test:
    /// a real git repository whose one file is committed enough times to
    /// clear the churn-hotspot threshold, combined with a hand-written LCOV
    /// snippet leaving most of the flagged function's lines uncovered.
    #[test]
    fn untested_hotspot_fires_when_complexity_churn_and_uncovered_lines_all_coincide() {
        let dir = TempDir::new("coverage-untested-hotspot");
        git(&dir, &["init", "-q", "-b", "main"]);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/hot.rs"), "fn hot() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);

        // Five more commits touching the same file — clears
        // `CHURN_HOTSPOT_THRESHOLD` (5) within the 14-day window.
        for i in 0..5 {
            std::fs::write(dir.join("src/hot.rs"), format!("fn hot() {{ {i} }}\n")).unwrap();
            git(&dir, &["add", "."]);
            git(&dir, &["commit", "-q", "-m", "rework"]);
        }

        let churn = crate::git::churn(&dir, UNTESTED_HOTSPOT_CHURN_WINDOW_DAYS).unwrap();
        // Lines 10..=20 belong to the function (11 lines, matching the DA
        // records below one-to-one); only 3 of them are covered.
        let functions = vec![function_info(dir.join("src/hot.rs"), 10, 12, 11)];

        let lcov = "\
SF:src/hot.rs
DA:10,1
DA:11,1
DA:12,1
DA:13,0
DA:14,0
DA:15,0
DA:16,0
DA:17,0
DA:18,0
DA:19,0
DA:20,0
end_of_record
";
        let coverage = parse_lcov(lcov, &dir);

        let findings = untested_hotspots(&functions, &churn, &coverage, &dir);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, UNTESTED_HOTSPOT_RULE);
        assert_eq!(
            findings[0].evidence_class,
            EvidenceClass::ExternalMeasurement
        );
        assert_eq!(
            findings[0].evidence,
            Some(json!({
                "cyclomatic_complexity": 12,
                "file_churn": churn[&PathBuf::from("src/hot.rs")],
                "lines_covered_pct": coverage.per_file[&PathBuf::from("src/hot.rs")].covered_pct(),
                "uncovered_line_count": 8,
            }))
        );
    }

    /// Same fixture as
    /// `untested_hotspot_fires_when_complexity_churn_and_uncovered_lines_all_coincide`,
    /// but with a leading `./` in the LCOV `SF:` path — regression coverage
    /// for the `resolve_lcov_path` fix: before it, this LCOV entry was keyed
    /// under `./src/hot.rs` while `for_file` looked up `src/hot.rs`, so the
    /// mismatch made a genuinely uncovered, high-complexity, high-churn
    /// function silently look like "no coverage data" and skip the rule
    /// entirely.
    #[test]
    fn untested_hotspot_fires_despite_a_leading_curdir_in_the_lcov_path() {
        let dir = TempDir::new("coverage-untested-hotspot-leading-curdir");
        git(&dir, &["init", "-q", "-b", "main"]);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/hot.rs"), "fn hot() {}\n").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "initial"]);

        for i in 0..5 {
            std::fs::write(dir.join("src/hot.rs"), format!("fn hot() {{ {i} }}\n")).unwrap();
            git(&dir, &["add", "."]);
            git(&dir, &["commit", "-q", "-m", "rework"]);
        }

        let churn = crate::git::churn(&dir, UNTESTED_HOTSPOT_CHURN_WINDOW_DAYS).unwrap();
        let functions = vec![function_info(dir.join("src/hot.rs"), 10, 12, 11)];

        let lcov = "\
SF:./src/hot.rs
DA:10,1
DA:11,1
DA:12,1
DA:13,0
DA:14,0
DA:15,0
DA:16,0
DA:17,0
DA:18,0
DA:19,0
DA:20,0
end_of_record
";
        let coverage = parse_lcov(lcov, &dir);

        let findings = untested_hotspots(&functions, &churn, &coverage, &dir);

        assert_eq!(findings.len(), 1);
    }

    /// Simulates a function whose `lines_of_code` (as `crate::complexity`
    /// computes it, over the full `syn` AST) spans an inactive
    /// `#[cfg(feature = "x")]` branch, while the LCOV report — generated
    /// from a real build with the feature off — never instruments those
    /// cfg-gated lines at all (not "uncovered": simply never compiled, so
    /// they never appear as `DA:` records). Those phantom lines inflate
    /// `uncovered_ratio`'s denominator (`function.lines_of_code`) without
    /// ever being able to inflate its numerator (`uncovered_in_function`
    /// only counts lines LCOV actually reported as zero-hit). The result is
    /// the opposite of a false positive: a function whose truly-compiled
    /// lines are 100% uncovered can still be diluted below
    /// `UNCOVERED_MAJORITY_RATIO` and silently escape `untested-hotspot`.
    /// Not fixed — doing so would mean sizing the denominator from LCOV's
    /// own instrumented-line set instead of `lines_of_code`, a bigger change
    /// than this test-only task's scope allows; documented here instead.
    #[test]
    fn untested_hotspot_misses_a_real_hotspot_when_cfg_gated_lines_inflate_the_span() {
        let dir = TempDir::new("coverage-untested-hotspot-cfg-blind-loc");
        let churn = HashMap::from([(PathBuf::from("src/hot.rs"), 10u32)]);
        // `lines_of_code` (14) spans lines 1..=14 as `syn` sees them
        // (cfg-blind); only lines 1..=4 are actually compiled and
        // instrumented — lines 5..=14 belong to an inactive
        // `#[cfg(feature = "x")]` branch and never appear in the LCOV file.
        let functions = vec![function_info(dir.join("src/hot.rs"), 1, 12, 14)];
        let mut coverage = CoverageReport::default();
        coverage.per_file.insert(
            PathBuf::from("src/hot.rs"),
            FileCoverage {
                lines_total: 4,
                lines_covered: 0,
                uncovered_lines: vec![1, 2, 3, 4],
            },
        );

        let findings = untested_hotspots(&functions, &churn, &coverage, &dir);

        assert!(
            findings.is_empty(),
            "cfg-blind lines_of_code dilutes uncovered_ratio (4/14 ≈ 29%) below the \
             50% threshold, even though the truly-compiled 4 lines are 100% uncovered"
        );
    }

    #[test]
    fn untested_hotspot_does_not_fire_for_low_complexity() {
        let dir = TempDir::new("coverage-untested-hotspot-low-complexity");
        let churn = HashMap::from([(PathBuf::from("src/hot.rs"), 10u32)]);
        let functions = vec![function_info(dir.join("src/hot.rs"), 1, 3, 20)];
        let mut coverage = CoverageReport::default();
        coverage.per_file.insert(
            PathBuf::from("src/hot.rs"),
            FileCoverage {
                lines_total: 20,
                lines_covered: 0,
                uncovered_lines: (1..=20).collect(),
            },
        );

        let findings = untested_hotspots(&functions, &churn, &coverage, &dir);
        assert!(findings.is_empty());
    }

    #[test]
    fn untested_hotspot_does_not_fire_for_low_churn() {
        let dir = TempDir::new("coverage-untested-hotspot-low-churn");
        let churn = HashMap::from([(PathBuf::from("src/hot.rs"), 1u32)]);
        let functions = vec![function_info(dir.join("src/hot.rs"), 1, 12, 20)];
        let mut coverage = CoverageReport::default();
        coverage.per_file.insert(
            PathBuf::from("src/hot.rs"),
            FileCoverage {
                lines_total: 20,
                lines_covered: 0,
                uncovered_lines: (1..=20).collect(),
            },
        );

        let findings = untested_hotspots(&functions, &churn, &coverage, &dir);
        assert!(findings.is_empty());
    }

    #[test]
    fn untested_hotspot_does_not_fire_for_high_coverage() {
        let dir = TempDir::new("coverage-untested-hotspot-high-coverage");
        let churn = HashMap::from([(PathBuf::from("src/hot.rs"), 10u32)]);
        let functions = vec![function_info(dir.join("src/hot.rs"), 1, 12, 20)];
        let mut coverage = CoverageReport::default();
        coverage.per_file.insert(
            PathBuf::from("src/hot.rs"),
            FileCoverage {
                lines_total: 20,
                lines_covered: 18,
                uncovered_lines: vec![1, 2],
            },
        );

        let findings = untested_hotspots(&functions, &churn, &coverage, &dir);
        assert!(findings.is_empty());
    }

    #[test]
    fn untested_hotspot_skips_a_function_whose_file_has_no_coverage_data() {
        let dir = TempDir::new("coverage-untested-hotspot-no-data");
        let churn = HashMap::from([(PathBuf::from("src/hot.rs"), 10u32)]);
        let functions = vec![function_info(dir.join("src/hot.rs"), 1, 12, 20)];
        let coverage = CoverageReport::default();

        let findings = untested_hotspots(&functions, &churn, &coverage, &dir);
        assert!(
            findings.is_empty(),
            "no coverage data must not be treated as 0% coverage"
        );
    }

    /// Builds a single-crate `Workspace` rooted at `dir`, with one authored
    /// `SourceFile` per `(relative_path, content)` pair — mirrors
    /// `crate::git`'s `workspace_with_sized_files` fixture helper, but writes
    /// real Rust source (needed here so `test_ratios` can parse `#[cfg(test)]`
    /// modules) instead of placeholder lines.
    fn workspace_with_files(dir: &Path, crate_name: &str, files: &[(&str, &str)]) -> Workspace {
        let mut source_files = Vec::new();
        for (relative_path, content) in files {
            let path = dir.join(relative_path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
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
    fn test_ratios_counts_a_tests_directory_file_as_test_loc_only() {
        let dir = TempDir::new("coverage-test-ratio-tests-dir");
        let workspace = workspace_with_files(
            &dir,
            "with-tests-dir",
            &[
                ("src/lib.rs", "pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n"),
                (
                    "tests/it.rs",
                    "#[test]\nfn it_adds() {\n    assert_eq!(1 + 1, 2);\n}\n",
                ),
            ],
        );

        let ratios = test_ratios(&workspace);

        assert_eq!(ratios.len(), 1);
        assert_eq!(ratios[0].crate_name, "with-tests-dir");
        assert_eq!(ratios[0].production_loc, 3);
        assert_eq!(ratios[0].test_loc, 4);
    }

    #[test]
    fn test_ratios_splits_an_inline_cfg_test_module_from_its_surrounding_file() {
        let dir = TempDir::new("coverage-test-ratio-inline-cfg-test");
        let content = "\
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_adds() {
        assert_eq!(add(1, 1), 2);
    }
}
";
        let workspace =
            workspace_with_files(&dir, "with-inline-cfg-test", &[("src/lib.rs", content)]);

        let ratios = test_ratios(&workspace);

        assert_eq!(ratios.len(), 1);
        // Lines 1-3 (the `add` function) plus the blank line before the
        // `#[cfg(test)]` module: 4 production lines.
        assert_eq!(ratios[0].production_loc, 4);
        // Lines 5-13: the `#[cfg(test)] mod tests { ... }` block, inclusive.
        assert_eq!(ratios[0].test_loc, 9);
    }

    #[test]
    fn test_ratios_is_zero_and_well_defined_for_a_crate_with_no_test_code() {
        let dir = TempDir::new("coverage-test-ratio-no-tests");
        let workspace = workspace_with_files(
            &dir,
            "no-tests",
            &[("src/lib.rs", "pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n")],
        );

        let ratios = test_ratios(&workspace);

        assert_eq!(ratios.len(), 1);
        assert_eq!(ratios[0].test_loc, 0);
        assert_eq!(ratios[0].production_loc, 3);
        assert_eq!(ratios[0].ratio(), Some(0.0));
    }

    #[test]
    fn test_ratios_are_computed_per_crate_not_pooled_across_the_workspace() {
        let dir = TempDir::new("coverage-test-ratio-multi-crate");
        let mut workspace = workspace_with_files(
            &dir.join("crate-a"),
            "crate-a",
            &[
                ("src/lib.rs", "pub fn a() {}\n"),
                ("tests/it.rs", "#[test]\nfn t() {}\n"),
            ],
        );
        let crate_b = workspace_with_files(
            &dir.join("crate-b"),
            "crate-b",
            &[("src/lib.rs", "pub fn b() {}\n")],
        );
        workspace.crates.extend(crate_b.crates);

        let ratios = test_ratios(&workspace);

        assert_eq!(ratios.len(), 2);
        let ratio_a = ratios.iter().find(|r| r.crate_name == "crate-a").unwrap();
        assert_eq!(ratio_a.production_loc, 1);
        assert_eq!(ratio_a.test_loc, 2);
        let ratio_b = ratios.iter().find(|r| r.crate_name == "crate-b").unwrap();
        assert_eq!(ratio_b.production_loc, 1);
        assert_eq!(ratio_b.test_loc, 0);
    }

    #[test]
    fn crate_test_ratio_ratio_is_none_when_production_loc_is_zero() {
        let ratio = CrateTestRatio {
            crate_name: "tests-only".to_string(),
            production_loc: 0,
            test_loc: 5,
        };
        assert_eq!(ratio.ratio(), None);
    }
}
