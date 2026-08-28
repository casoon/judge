//! Codebase intelligence for Rust workspaces.

pub mod advisory;
pub mod baseline;
#[cfg(feature = "deep")]
pub mod deep;
pub mod finding;
mod functions;
pub mod health_score;
pub mod impact;
pub mod ingest;
pub mod markdown;
pub mod pattern_baseline;
#[cfg(feature = "deep")]
pub mod reachability;
pub mod refactor_map;
pub mod report;
pub mod rule_registry;
pub mod rules;
pub mod sarif;
pub mod suppression;
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
