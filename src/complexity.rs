//! Fast-tier complexity analysis: cyclomatic complexity per function via `syn`,
//! no build required (see todo.md §2.1, §3.C).

use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};
use syn::{Expr, ItemFn};

use crate::functions::walk_functions;

/// Cyclomatic complexity and size of a single function or method.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub qualified_name: String,
    pub file: PathBuf,
    pub line: usize,
    pub cyclomatic: u32,
    pub lines_of_code: usize,
}

#[derive(Debug)]
pub enum ComplexityError {
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, syn::Error),
}

impl std::fmt::Display for ComplexityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "{}: failed to read file: {err}", path.display()),
            Self::Parse(path, err) => write!(f, "{}: failed to parse: {err}", path.display()),
        }
    }
}

impl std::error::Error for ComplexityError {}

/// Parses a single Rust source file and returns the complexity of every
/// function, method, and default trait-method body it contains.
pub fn analyze_file(path: &Path) -> Result<Vec<FunctionInfo>, ComplexityError> {
    let source = std::fs::read_to_string(path)
        .map_err(|err| ComplexityError::Io(path.to_path_buf(), err))?;
    let ast =
        syn::parse_file(&source).map_err(|err| ComplexityError::Parse(path.to_path_buf(), err))?;

    let mut functions = Vec::new();
    walk_functions(&ast, |site| {
        let mut complexity = ComplexityVisitor { complexity: 1 };
        complexity.visit_block(site.block);

        let start_line = site.span.start().line;
        let end_line = site.span.end().line.max(start_line);

        functions.push(FunctionInfo {
            qualified_name: site.qualified_name,
            file: path.to_path_buf(),
            line: start_line,
            cyclomatic: complexity.complexity,
            lines_of_code: end_line - start_line + 1,
        });
    });
    Ok(functions)
}

/// Aggregated complexity results across a set of files, keeping analyzable
/// functions separate from files that could not be parsed.
#[derive(Debug, Default)]
pub struct WorkspaceComplexity {
    pub functions: Vec<FunctionInfo>,
    pub errors: Vec<ComplexityError>,
}

/// Runs [`analyze_file`] over every path in `source_files` and aggregates the results.
pub fn analyze_workspace<'a>(
    source_files: impl IntoIterator<Item = &'a PathBuf>,
) -> WorkspaceComplexity {
    let mut report = WorkspaceComplexity::default();
    for path in source_files {
        match analyze_file(path) {
            Ok(mut functions) => report.functions.append(&mut functions),
            Err(err) => report.errors.push(err),
        }
    }
    report
}

/// Counts branch points inside a single function body (cyclomatic complexity,
/// starting from a base of 1). Nested `fn` items are skipped here since
/// [`walk_functions`] analyzes them as their own, separate functions.
struct ComplexityVisitor {
    complexity: u32,
}

impl<'ast> Visit<'ast> for ComplexityVisitor {
    fn visit_expr(&mut self, expr: &'ast Expr) {
        match expr {
            Expr::If(_) | Expr::While(_) | Expr::ForLoop(_) | Expr::Loop(_) | Expr::Try(_) => {
                self.complexity += 1;
            }
            Expr::Match(node) => {
                self.complexity += node.arms.len().saturating_sub(1) as u32;
                self.complexity +=
                    node.arms.iter().filter(|arm| arm.guard.is_some()).count() as u32;
            }
            Expr::Binary(node) if matches!(node.op, syn::BinOp::And(_) | syn::BinOp::Or(_)) => {
                self.complexity += 1;
            }
            _ => {}
        }
        visit::visit_expr(self, expr);
    }

    fn visit_item_fn(&mut self, _node: &'ast ItemFn) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    #[test]
    fn cyclomatic_complexity_counts_branches() {
        let dir = TempDir::new("complexity-branches");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            r#"
fn straight_line() {
    let _ = 1 + 1;
}

fn single_if(x: i32) {
    if x > 0 {
        let _ = x;
    }
}

fn if_else_if(x: i32) {
    if x > 0 {
        let _ = x;
    } else if x < 0 {
        let _ = x;
    }
}

fn boolean_operators(a: bool, b: bool) -> bool {
    a && b || a
}

fn loops(x: i32) {
    let mut i = 0;
    while i < x {
        i += 1;
    }
    for j in 0..x {
        let _ = j;
    }
    loop {
        break;
    }
}

fn try_operator() -> Result<i32, ()> {
    let x: Result<i32, ()> = Ok(1);
    Ok(x?)
}

fn match_arms(x: i32) -> i32 {
    match x {
        1 => 1,
        2 | 3 => 2,
        n if n > 10 => 3,
        _ => 0,
    }
}
"#,
        )
        .unwrap();

        let functions = analyze_file(&file).unwrap();
        let complexity = |name: &str| {
            functions
                .iter()
                .find(|f| f.qualified_name == name)
                .unwrap_or_else(|| panic!("missing function {name}"))
                .cyclomatic
        };

        assert_eq!(complexity("straight_line"), 1);
        assert_eq!(complexity("single_if"), 2);
        assert_eq!(complexity("if_else_if"), 3);
        assert_eq!(complexity("boolean_operators"), 3);
        assert_eq!(complexity("loops"), 4);
        assert_eq!(complexity("try_operator"), 2);
        assert_eq!(complexity("match_arms"), 5);
    }

    #[test]
    fn nested_fn_is_analyzed_separately_and_excluded_from_outer() {
        let dir = TempDir::new("complexity-nested-fn");
        let file = dir.join("lib.rs");
        std::fs::write(
            &file,
            r#"
fn outer(x: i32) -> i32 {
    fn inner(y: i32) -> i32 {
        if y > 0 { 1 } else { 0 }
    }
    if x > 0 {
        inner(x)
    } else {
        0
    }
}
"#,
        )
        .unwrap();

        let functions = analyze_file(&file).unwrap();
        assert_eq!(functions.len(), 2);

        let outer = functions
            .iter()
            .find(|f| f.qualified_name == "outer")
            .unwrap();
        let inner = functions
            .iter()
            .find(|f| f.qualified_name == "inner")
            .unwrap();
        assert_eq!(outer.cyclomatic, 2);
        assert_eq!(inner.cyclomatic, 2);
    }

    #[test]
    fn analyze_file_reports_parse_errors() {
        let dir = TempDir::new("complexity-parse-error");
        let file = dir.join("broken.rs");
        std::fs::write(&file, "fn broken( {").unwrap();

        let err = analyze_file(&file).unwrap_err();
        match err {
            ComplexityError::Parse(path, _) => assert_eq!(path, file),
            other => panic!("expected a parse error, got {other:?}"),
        }
    }

    #[test]
    fn analyze_file_reports_io_errors_for_missing_files() {
        let missing = PathBuf::from("/nonexistent/judge-test-file-does-not-exist.rs");
        let err = analyze_file(&missing).unwrap_err();
        match err {
            ComplexityError::Io(path, _) => assert_eq!(path, missing),
            other => panic!("expected an io error, got {other:?}"),
        }
    }

    #[test]
    fn analyze_workspace_aggregates_functions_and_errors() {
        let dir = TempDir::new("complexity-workspace");
        let good = dir.join("good.rs");
        let bad = dir.join("bad.rs");
        std::fs::write(&good, "fn ok() {}").unwrap();
        std::fs::write(&bad, "fn broken( {").unwrap();

        let files = [good, bad];
        let report = analyze_workspace(files.iter());

        assert_eq!(report.functions.len(), 1);
        assert_eq!(report.functions[0].qualified_name, "ok");
        assert_eq!(report.errors.len(), 1);
    }
}
