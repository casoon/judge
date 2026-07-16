use std::collections::HashMap;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use judge::AnalysisTier;
use judge::complexity::FunctionInfo;
use judge::duplication::DupeMode;
use judge::ingest::Workspace;

#[derive(Debug, Parser)]
#[command(name = "cargo judge", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Find duplicated function bodies (clone families).
    Dupes {
        /// How aggressively function bodies must match to count as duplicates.
        #[arg(long, value_enum, default_value = "mild")]
        mode: DupeModeArg,
    },
    /// Show the repository health summary, including slop signals.
    Health {
        /// Include the numeric health score.
        #[arg(long)]
        score: bool,
    },
    /// Initialize judge configuration in a workspace.
    Init,
    /// Show detected entry points, tiers, and cache status.
    Inspect,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DupeModeArg {
    Strict,
    Mild,
}

impl From<DupeModeArg> for DupeMode {
    fn from(value: DupeModeArg) -> Self {
        match value {
            DupeModeArg::Strict => Self::Strict,
            DupeModeArg::Mild => Self::Mild,
        }
    }
}

fn main() {
    let mut args = std::env::args_os().collect::<Vec<_>>();
    if args.get(1).is_some_and(|arg| arg == "judge") {
        args.remove(1);
    }
    let cli = Cli::parse_from(args);

    match cli.command {
        None => run_health(false),
        Some(Command::Dupes { mode }) => run_dupes(mode),
        Some(Command::Health { score }) => run_health(score),
        Some(Command::Init) => println!("judge init is not implemented yet"),
        Some(Command::Inspect) => run_inspect(),
    }
}

fn run_dupes(mode: DupeModeArg) {
    let workspace = match judge::ingest::load(None) {
        Ok(workspace) => workspace,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };

    let source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    let report = judge::duplication::analyze_workspace(source_files, mode.into());

    println!(
        "mode: {}",
        match mode {
            DupeModeArg::Strict => "strict",
            DupeModeArg::Mild => "mild",
        }
    );
    println!("clone families: {}", report.families.len());
    if !report.errors.is_empty() {
        println!("files skipped (parse errors): {}", report.errors.len());
        for err in &report.errors {
            println!("  {err}");
        }
    }

    for (index, family) in report.families.iter().take(15).enumerate() {
        println!();
        println!("family #{} — {} members", index + 1, family.members.len());
        for member in &family.members {
            println!(
                "  {:>3} lines  {}:{}  {}",
                member.lines_of_code,
                member.file.display(),
                member.line,
                member.qualified_name
            );
        }
    }
}

fn run_health(show_score: bool) {
    let workspace = match judge::ingest::load(None) {
        Ok(workspace) => workspace,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };

    let source_files = workspace
        .crates
        .iter()
        .flat_map(|krate| krate.source_files.iter());
    let report = judge::complexity::analyze_workspace(source_files);

    println!("functions analyzed: {}", report.functions.len());
    if !report.errors.is_empty() {
        println!("files skipped (parse errors): {}", report.errors.len());
        for err in &report.errors {
            println!("  {err}");
        }
    }

    let mut functions = report.functions;
    functions.sort_by_key(|function| std::cmp::Reverse(function.cyclomatic));

    println!();
    println!("top complexity (cyclomatic):");
    for function in functions.iter().take(15) {
        println!(
            "  {:>3}  {}:{}  {}",
            function.cyclomatic,
            function.file.display(),
            function.line,
            function.qualified_name
        );
    }

    println!();
    print_hotspots(&workspace, &functions);

    if show_score {
        println!();
        println!(
            "health score: not implemented yet (needs baselines and crate-type profiles, see todo.md §4)"
        );
    }
}

/// Hotspot = complexity × change frequency (see todo.md §3.E). Files with no
/// recorded churn (or no git history at all) are left out rather than shown
/// as zero-risk.
fn print_hotspots(workspace: &Workspace, functions: &[FunctionInfo]) {
    let churn = match judge::git::churn(&workspace.root, judge::git::DEFAULT_WINDOW_DAYS) {
        Ok(churn) => churn,
        Err(err) => {
            println!("hotspots: unavailable ({err})");
            return;
        }
    };
    if churn.is_empty() {
        println!(
            "hotspots: no git history in the last {} days",
            judge::git::DEFAULT_WINDOW_DAYS
        );
        return;
    }

    let mut file_complexity: HashMap<PathBuf, u32> = HashMap::new();
    for function in functions {
        *file_complexity.entry(function.file.clone()).or_insert(0) += function.cyclomatic;
    }

    let mut hotspots: Vec<(PathBuf, u32, u32)> = file_complexity
        .into_iter()
        .filter_map(|(file, complexity)| {
            let relative = file.strip_prefix(&workspace.root).ok()?;
            let changes = *churn.get(relative)?;
            (changes > 0).then_some((file, complexity, changes))
        })
        .collect();
    hotspots.sort_by_key(|(_, complexity, changes)| std::cmp::Reverse(complexity * changes));

    println!(
        "hotspots (complexity × changes in the last {} days):",
        judge::git::DEFAULT_WINDOW_DAYS
    );
    for (file, complexity, changes) in hotspots.iter().take(15) {
        println!(
            "  {:>6}  {complexity} × {changes} changes  {}",
            complexity * changes,
            file.display()
        );
    }
}

fn run_inspect() {
    let workspace = match judge::ingest::load(None) {
        Ok(workspace) => workspace,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };

    println!("workspace root: {}", workspace.root.display());
    println!("crates: {}", workspace.crates.len());
    for krate in &workspace.crates {
        println!();
        println!("  {} {}", krate.name, krate.version);
        println!("    manifest: {}", krate.manifest_path.display());
        println!("    source files: {}", krate.source_files.len());
        if krate.entry_points.is_empty() {
            println!("    entry points: none");
        } else {
            println!("    entry points:");
            for entry in &krate.entry_points {
                println!(
                    "      [{}] {} — {}",
                    entry.kind.label(),
                    entry.name,
                    entry.path.display()
                );
            }
        }
    }

    println!();
    println!("tiers:");
    println!("  fast: available");
    println!(
        "  deep: {}",
        if AnalysisTier::Deep.is_available() {
            "available"
        } else {
            "not available (build with --features deep)"
        }
    );
    println!();
    println!("cache: not implemented yet");
}
