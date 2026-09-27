---
title: Duplicate code
description: How dupes groups repeated token spans into clone families, and how to mark a duplicate as intentional.
order: 4
---

```sh
cargo judge dupes                  # mild mode, production code
cargo judge dupes --mode strict    # also: weak, semantic
cargo judge dupes --include-tests  # test-only code is opt-in
cargo judge dupes --min-tokens 40  # ignore spans shorter than 40 tokens (default 20)
```

`dupes` groups duplicated token spans into clone families and orders them by repeated tokens.
The summary ranks the families; the detail lists every member with its span and function. The
[clone families example](../../../showcase/clone-families/) shows judge's own tree. Duplication
in generated files is skipped unless you pass `--include-generated`.

The ranking is a list of inspection candidates, not an automatic merge recommendation.

## Intentional duplicates

For a clearly intentional duplicate — an externally specified protocol adapter, or a deliberately
parallel implementation — put a reasoned comment immediately before each affected function:

```rust
// judge-dupe-ignore: required external protocol shape; keeping variants parallel
fn encode_v2(/* … */) { /* … */ }
```

The directive suppresses only the next function body. It requires a non-empty reason and fails
if it is not directly followed by a function, so a stale comment cannot silently suppress
unrelated code. For a deliberately scoped range of several items:

```rust
// judge-dupe-off: lookup tables kept parallel to the specification
// …
// judge-dupe-on
```

Use these sparingly. They document an exception; they do not replace extracting a shared
abstraction.

## Declarative macros

A brace-delimited macro call with named fields, such as `candidate! { evidence: ..., migration:
... }`, is treated as declarative configuration, not duplicated executable code. Ordinary macro
calls stay part of the token analysis.
