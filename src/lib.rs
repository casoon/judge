//! Codebase intelligence for Rust workspaces.

pub mod baseline;
pub mod boundaries;
pub mod complexity;
#[cfg(feature = "deep")]
pub mod dead_code;
#[cfg(feature = "deep")]
pub mod deep;
pub mod deps;
pub mod duplication;
pub mod finding;
mod functions;
pub mod gate;
pub mod git;
pub mod health_score;
pub mod ingest;
pub mod ownership;
#[cfg(feature = "deep")]
pub mod reachability;
pub mod slop;
mod slop_text;
pub mod slopsquat;
#[cfg(test)]
mod test_util;

/// Analysis tier selected for a run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisTier {
    Fast,
    Deep,
}

impl AnalysisTier {
    /// Returns whether this build contains the deep rust-analyzer integration.
    pub const fn is_available(self) -> bool {
        match self {
            Self::Fast => true,
            Self::Deep => cfg!(feature = "deep"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AnalysisTier;

    #[test]
    fn fast_tier_is_always_available() {
        assert!(AnalysisTier::Fast.is_available());
    }

    #[test]
    fn deep_tier_matches_feature_flag() {
        assert_eq!(AnalysisTier::Deep.is_available(), cfg!(feature = "deep"));
    }
}
