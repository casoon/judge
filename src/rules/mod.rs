//! Rule/detector modules: each one analyses the workspace for one concern
//! (structural slop, duplication, dead code, boundaries, ...) and produces
//! [`crate::finding::Finding`]s. Grouped here for navigability (see GitHub
//! issue #41) — this is a pure module-path reorganization, not a change to
//! any rule's logic or evidence.

pub mod api_surface;
#[cfg(feature = "deep")]
pub mod api_surface_deep;
pub mod boundaries;
#[cfg(feature = "deep")]
pub mod boundaries_deep;
pub mod complexity;
#[cfg(feature = "deep")]
pub mod dead_code;
#[cfg(feature = "deep")]
pub mod dead_trait_impl;
pub mod dep_graph;
pub mod deps;
pub mod duplication;
#[cfg(feature = "deep")]
pub mod feature_matrix;
pub mod module_graph;
pub mod pattern;
pub mod principle;
pub mod security;
pub mod slop;
pub mod slop_structural;
#[cfg(feature = "deep")]
pub mod slop_structural_deep;
pub(crate) mod slop_text;
pub mod slopsquat;
