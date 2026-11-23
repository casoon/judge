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

## --expand

```sh
cargo judge dead-code --expand
cargo judge explain my_crate::config::default_port --why-live --expand
```

By default the workspace is loaded without a proc-macro server and without build-script outputs.
`--expand` (or `[deep] expand = true` in `judge.toml`) loads the full picture: judge starts the
active toolchain's proc-macro server (`rust-analyzer-proc-macro-srv` from the `rust-analyzer`
rustup component) and runs `cargo check` to load build-script outputs. References that only exist
in generated code then count — a function named in `#[serde(default = "…")]`, or one called only
from code a `build.rs` writes to `OUT_DIR`. In `explain --why-live`, an edge that only exists in
generated code is marked `generated`.

**`--expand` runs the workspace's build scripts and proc macros, so it executes workspace code.**
Use it only on code you trust. The check builds into `target/rust-analyzer`, so your own build
is not invalidated.

If the proc-macro server does not start or a build script fails, the command stops with exit
code 2 and names the cause. It never falls back to the unexpanded load.

Every output format states the load fidelity: the TTY header and `analysis_universe.load_fidelity`
in JSON and SARIF read `proc_macros: expanded | not expanded` and
`build_scripts: loaded | not loaded`.

On judge's own repository (about 74,000 lines, release build, Apple Silicon, machine under
heavy parallel load), `cargo judge dead-code` took 46 s, `cargo judge dead-code --expand` took
75 s on the first run (including `cargo check` of the build scripts and proc macros) and 63 s on a
repeated run.

## Known limits

- Without `--expand`, code produced by proc macros or `build.rs` is invisible to the analysis. A
  function only called from generated code is reported as unused.
- A reference from generated code counts like any other: it makes an item used when it comes
  from another workspace crate, or when its generated caller is reachable from an entry point.
  A derive-generated trait impl is not an entry point, so a `pub` function only named by a derive
  in its own crate stays reported.
- Generic registration macros are not recognised. An item reached only through one can be
  reported as unused.
