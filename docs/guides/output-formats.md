---
title: Output formats
description: Terminal triage, versioned JSON, SARIF 2.1.0 and Markdown — what each contains and where it is written.
order: 2
---

`--format` selects the output of a report command: `tty` (default), `json`, `sarif` or
`markdown`. The terminal and Markdown views are summaries for people; JSON is the exhaustive
contract for tools.

## Terminal

The combined `cargo judge` view groups findings by rule and shows one representative location
per group, separated into evidence-backed findings and advisory heuristics, followed by next
steps. `--details` lists every location. Colour follows `--color auto|always|never`; `auto` uses
colour only on a terminal and honours `NO_COLOR`.

## JSON

```sh
cargo judge --format json                       # .judge/judge.json
cargo judge dupes --format json --output reports/dupes.json
```

Every report command writes versioned JSON, by default to `.judge/<command>.json`, or to
`--output PATH`. Every artifact starts with a `header`, followed by the command payload. The
header records the working directory, the output path, a generation timestamp, a short command
description and an **assessment**: `informational`, `review_recommended`, `analysis_incomplete`
or `blocking_findings`. The assessment is a triage hint, not a refactoring instruction.

The combined report's payload carries `schema_version`, `analysis_universe` (judge version,
tier, targets, features, whether tests or generated code were included), `counts`, `errors` and
the complete `findings`. The `map`, `impact` and progress contracts are covered by CLI tests, so
tooling can rely on their schema versions.

## SARIF

```sh
cargo judge --format sarif > judge.sarif
```

SARIF 2.1.0 is available on the report-producing commands and goes to stdout, ready for a code
scanning upload.

## Markdown

```sh
cargo judge --format markdown                          # .judge/judge.md
cargo judge compare .judge/baseline.json --format markdown
```

For the combined run, Markdown renders the grouped summary for a pull request or issue: an
executive summary, evidence-backed and advisory groups with counts and representative locations,
and next steps — never a raw per-finding dump. For `compare` it renders the delta table. See the
[Markdown example](../../../showcase/markdown-summary/).

## Progress events

```sh
cargo judge --progress judge-progress.jsonl
```

For the bare combined run, `--progress PATH` writes a flushed JSON Lines stream. Each record has
`schema_version`, `sequence`, `event` (`phase_started` or `phase_completed`) and `phase`. It
reports the analysis lifecycle only, never provisional findings, so an agent can follow a long
run.
