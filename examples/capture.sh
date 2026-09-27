#!/usr/bin/env bash
# Regenerates the fixtures in examples/ by running judge on its own source tree.
# They are shown on the project site (site/src/showcase.ts). Run from the repository root
# after `cargo build --release`.
#
# Two edits are applied to the raw output, nothing else:
# - the absolute workspace root is removed, so paths read `src/...` instead of the
#   machine-specific checkout path;
# - OSC 8 terminal hyperlinks (file:// links around source locations) are removed; the
#   visible text stays.
set -euo pipefail

root="$(pwd)"
bin="$root/target/release/cargo-judge"
out="$root/examples"

clean() {
  perl -pe "s#\\e\\]8;;[^\\e]*\\e\\\\##g; s#\\Q$root/\\E##g"
}

"$bin" --color always | clean > "$out/summary.ansi"
"$bin" health --score | clean > "$out/health.txt"
"$bin" dupes | clean > "$out/dupes.txt"
"$bin" refactor | clean > "$out/refactor.txt"
"$bin" map | clean > "$out/map.txt"
"$bin" explain-rule swallowed-result | clean > "$out/explain-rule.txt"
"$bin" --format markdown --output "$out/summary.md" > /dev/null

# Baseline delta: the tree right after the 0.7.0 source reorganisation (8cfda89) as the
# baseline, compared with the checked-out tree. `compare` exits 1 on a failing verdict.
base="$(mktemp -d)"
git archive 8cfda89 | tar -x -C "$base"
(cd "$base" && "$bin" --save-baseline > /dev/null)
"$bin" compare "$base/.judge/baseline.json" | clean > "$out/compare.txt" || true
rm -r "$base"
