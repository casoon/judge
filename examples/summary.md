# Judge summary

- 671 evidence-backed findings · 333 advisory heuristics
- boundary rules: 0 not checked (no judge.toml)

## Evidence-backed findings: 671

| rule | count | representative location |
|---|---|---|
| duplicate-code | 635 | src/rules/principle.rs:550 (build_functional_core_imperative_shell_heuristic) |
| panic-in-lib | 22 | src/advisory/coverage.rs:336 (untested_hotspots) |
| suppression-debt | 11 | src/commands/combined.rs:178 (clippy::too_many_arguments) |
| swallowed-result | 2 | src/rules/slopsquat.rs:356 (write_cache) |
| restating-comment | 1 | src/rules/complexity.rs:1457 (tests::maintainability_index_matches_hand_calculation) |

## Advisory heuristics (no verdict or score effect): 333

| rule | count | representative location |
|---|---|---|
| complexity-inflation | 243 | src/advisory/advisories.rs:330 (known_vulnerability_finding) |
| integer-cast-risk | 39 | src/advisory/clippy_import.rs:87 (parse_clippy_report) |
| maintainability-index | 39 | src/advisory/advisories.rs:1 (src/advisory/advisories.rs) |
| silent-default | 9 | src/advisory/advisories.rs:164 (parse_audit_report) |
| abstraction-inflation | 3 | src/rules/principle.rs:518 (Finder) |

## Next steps

- cargo judge dupes clone families, grouped and prioritized
- cargo judge --details every finding and location
- cargo judge --format json full machine-readable report in .judge/judge.json
