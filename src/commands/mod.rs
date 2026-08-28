//! CLI command implementations for the `cargo-judge` binary. Grouped here
//! for navigability (see GitHub issue #41) — a pure module-path
//! reorganization, not a behavior change. Binary-crate-internal only (not
//! part of the `judge` library's public API).

pub(crate) mod advisory_commands;
pub(crate) mod analysis_commands;
pub(crate) mod baseline_output;
pub(crate) mod cli;
pub(crate) mod combined;
pub(crate) mod combined_analysis;
pub(crate) mod deep_commands;
pub(crate) mod health_command;
pub(crate) mod workspace_commands;
