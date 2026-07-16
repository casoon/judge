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
    let source =
        std::fs::read_to_string(path).map_err(|err| ComplexityError::Io(path.to_path_buf(), err))?;
    let ast = syn::parse_file(&source).map_err(|err| ComplexityError::Parse(path.to_path_buf(), err))?;

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
                self.complexity += node.arms.iter().filter(|arm| arm.guard.is_some()).count() as u32;
            }
            Expr::Binary(node)
                if matches!(node.op, syn::BinOp::And(_) | syn::BinOp::Or(_)) =>
            {
                self.complexity += 1;
            }
            _ => {}
        }
        visit::visit_expr(self, expr);
    }

    fn visit_item_fn(&mut self, _node: &'ast ItemFn) {}
}
