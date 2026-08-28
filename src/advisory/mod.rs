//! Advisory-only modules: heuristic signals that never affect the
//! verdict/exit code (mutation-testing import, clippy import, coverage
//! import, dependency advisories). Grouped here for navigability (see
//! GitHub issue #41) — a pure module-path reorganization.

pub mod advisories;
pub mod clippy_import;
pub mod coverage;
pub mod mutants;
