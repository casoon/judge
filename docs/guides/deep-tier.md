---
title: Deep Tier
description: rust-analyzer-based analysis behind the deep feature — dead-code and explain --why-live, with their stated limits.
order: 5
---

The Deep Tier loads the workspace into rust-analyzer (`ra_ap_ide`, `ra_ap_load-cargo`) to work
with real reference data instead of syntax-level guesses. It is compiled only with the `deep`
feature, which builds the `ra_ap_*` crates and takes noticeably longer than the default build.

```sh
cargo install cargo-judge --features deep
cargo judge inspect   # "deep: available" once the feature is compiled in
```

## dead-code

```sh
cargo judge dead-code
cargo judge dead-code --include-tests
```

Reports `unused-pub-workspace`: `pub` items with no reference from another workspace crate
**and** no reachability from a recognised entry point of their own crate. That means "no use
found in the examined view", not proven dead. `--include-tests` counts `#[test]`-only references
as usage (off by default). Findings carry their evidence — root-set size, searched crates and the
reason for the confidence — so you can judge it yourself.

## explain --why-live

```sh
cargo judge explain my_crate::parser::parse --why-live
```

Prints the shortest evidenced call path from a recognised entry point to the item. Entry points
are `fn main` in binaries and examples, tests and benches with `--include-tests`, and
`#[no_mangle]`, `#[export_name]` and `#[wasm_bindgen]` items always. Each edge is classified as
`static`, `dynamic`, `macro`, `generated` or `unknown`.

## Known limits

- The workspace is loaded without a proc-macro server and without running build scripts, so
  code produced by proc macros or `build.rs` is invisible to the analysis.
- Generic registration macros are not recognised. An item reached only through one can be
  reported as unused.
