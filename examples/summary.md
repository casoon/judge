# Judge summary

- 743 evidence-backed findings · 359 advisory heuristics
- boundary rules: 0 not checked (no judge.toml)

## Evidence-backed findings: 743

| rule | count | representative location |
|---|---|---|
| duplicate-code | 696 | src/rules/principle.rs:549 (build_functional_core_imperative_shell_heuristic) |
| panic-in-lib | 29 | src/advisory/coverage.rs:321 (untested_hotspots) |
| suppression-debt | 14 | src/commands/analysis_commands.rs:1485 (clippy::too_many_arguments) |
| swallowed-result | 3 | src/main.rs:4017 (tests::write_rule_level_fixture) [cfg(test)] |
| restating-comment | 1 | src/rules/complexity.rs:1459 (tests::maintainability_index_matches_hand_calculation) [cfg(test)] |

## Advisory heuristics (no verdict or score effect): 359

| rule | count | representative location |
|---|---|---|
| complexity-inflation | 257 | src/advisory/advisories.rs:346 (known_vulnerability_finding) |
| maintainability-index | 44 | src/advisory/advisories.rs:1 (src/advisory/advisories.rs) |
| integer-cast-risk | 41 | src/advisory/clippy_import.rs:87 (parse_clippy_report) |
| silent-default | 13 | src/advisory/advisories.rs:174 (parse_audit_report) |
| abstraction-inflation | 4 | src/cfg.rs:327 (CfgIndexBuilder) |

## Next steps

- cargo judge dupes clone families, grouped and prioritized
- cargo judge --details every finding and location
- cargo judge --format json full machine-readable report in .judge/judge.json
