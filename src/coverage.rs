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

use crate::complexity::FunctionInfo;
use crate::finding::{EvidenceClass, Finding, Location, OneBasedLine, Origin, Severity};

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
/// absolute and resolve under it; already-relative paths are kept as given
/// (LCOV from `cargo-llvm-cov` run at the workspace root emits both forms
/// depending on invocation). After parsing, every resulting path is checked
/// for existence and recorded in [`CoverageReport::missing_files`] if it
/// isn't found — see todo.md §J point 2.
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
        path
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
}
