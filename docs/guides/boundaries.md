---
title: Crate boundaries
description: Declare which crates may depend on which in judge.toml and check them with cargo judge boundaries.
order: 3
---

Architecture rules need an explicit statement of intent, so judge never guesses them. Boundary
checks are opt-in: without a `judge.toml` in the workspace root, `cargo judge boundaries` checks
no boundary rules, and the combined report says so in its analysis context.

## Crate boundaries

```toml
# judge.toml
[[boundary]]
name = "ui-must-not-touch-db"
from = ["ui"]
forbidden = ["db"]
reach = "transitive"

[[boundary]]
name = "core-needs-approved-io"
from = ["core"]
required = ["io-abstraction"]
reach = "direct"
```

A rule names `forbidden` crates, `required` crates, or both. `reach` is `direct` or `transitive`.
A rule that names a crate the workspace does not have is a configuration error (exit 2), unless
it sets `allow_empty = true`.

For layered architectures, a `[layers]` table with a preset expands a compact crate-to-layer
assignment into the same rules: inner layers may not reach outer layers.

## Module boundaries

`[[module_boundary]]` rules work inside one crate's module tree. `from` is a single module path
prefix, `forbidden` lists module prefixes it must not reference:

```toml
[[module_boundary]]
name = "domain-stays-pure"
crate = "app"
from = "domain"
forbidden = ["infrastructure"]
```

## Checking

```sh
cargo judge boundaries                # rule violations and dependency cycles
cargo judge boundaries --graph mermaid  # print the crate graph instead (also: dot)
```

`--graph` does not need `judge.toml`; it prints the existing crate dependency graph and exits.
