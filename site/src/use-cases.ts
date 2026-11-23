import { url } from '@casoon/pages-theme/url';
import type { UseCase, UseCasesPage } from '@casoon/pages-theme/use-cases';

export const lead: UseCasesPage['lead'] =
  'Five jobs judge gets used for. Each one names the commands and where to read on.';

export const useCases: UseCase[] = [
  {
    slug: 'ci-gate',
    eyebrow: 'CI · Baseline',
    title: 'Keep a refactoring from making the workspace worse',
    body: 'Accept today’s state once, then let every later tree answer one question: did this change add evidence-backed findings? Old findings stay listed but never block, so you can start on a codebase that is far from clean.',
    tags: ['CI', 'Baseline'],
    steps: [
      'Run judge on a tree you accept and save its findings as `.judge/baseline.json`.',
      'Commit the baseline, or restore it as a CI artifact.',
      'Let CI compare every later tree with it: exit code 1 when a new gating finding appears, 0 otherwise.',
    ],
    code: {
      title: 'Terminal, then the CI step',
      label: 'sh',
      lang: 'sh',
      code: `# once, on the accepted tree
cargo judge --save-baseline
git add .judge/baseline.json
# the step in .github/workflows/ci.yml
cargo judge compare .judge/baseline.json`,
      marks: [
        { line: 2, n: 1 },
        { line: 3, n: 2 },
        { line: 5, n: 3 },
      ],
    },
    links: [
      { label: 'Baselines and CI', href: url('docs/guides/baselines-and-ci/') },
      { label: 'A real compare run', href: url('showcase/baseline-compare/') },
    ],
  },
  {
    slug: 'agents',
    eyebrow: 'Coding agents',
    title: 'Review what a coding agent changed',
    body: 'judge reads only the checked-out tree, never Git history or authorship, so code from a person and code from an agent get the same findings. The agent can ask for them itself through the local MCP adapter.',
    tags: ['Agents', 'JSON', 'MCP'],
    specs: [
      { term: 'Command', value: '`cargo judge --format json`' },
      { term: 'MCP', value: '`judge-mcp`, stdio, runs the local binary' },
      { term: 'Patches', value: 'None: judge ranks candidates, it never edits code' },
    ],
    links: [
      { label: 'MCP adapter', href: url('docs/guides/mcp/') },
      { label: 'Output formats', href: url('docs/guides/output-formats/') },
    ],
  },
  {
    slug: 'crate-split',
    eyebrow: 'Deep Tier · Dead code',
    title: 'Find the public API a crate split left behind',
    body: 'After moving code between crates, some `pub` items have no caller left in the workspace. With the Deep Tier, judge finds them from rust-analyzer’s reference data and shows the route by which anything that is still live gets reached.',
    tags: ['Deep Tier', 'Workspaces'],
    specs: [
      { term: 'Build', value: '`cargo install cargo-judge --features deep`' },
      { term: 'Commands', value: '`cargo judge dead-code`, `cargo judge explain <path> --why-live`' },
      { term: 'Generated code', value: '`--expand` counts calls from proc macros and build scripts' },
    ],
    links: [{ label: 'Deep Tier guide', href: url('docs/guides/deep-tier/') }],
  },
  {
    slug: 'adopt',
    eyebrow: 'judge.toml',
    title: 'Adopt the rules your team agrees with',
    body: 'Not every rule fits every workspace. Switch a rule off, demote it to advisory or promote it to gating in `judge.toml`; every report names the changed rules in its header, so a verdict is never relaxed silently.',
    tags: ['Configuration', 'Teams'],
    specs: [
      { term: 'Setting', value: '`[rules.<id>] level = "off" | "advisory" | "gating"`' },
      { term: 'Visible in', value: 'Every report header, every output format' },
      { term: 'Starter file', value: '`cargo judge init`' },
    ],
    links: [{ label: 'Rule levels', href: url('docs/reference/rules/#rule-levels') }],
  },
  {
    slug: 'release-profile',
    eyebrow: 'Cargo profiles',
    title: 'Ship the release build you meant to ship',
    body: 'A debugging leftover in `[profile.release]` builds an unoptimised binary, keeps `debug_assert!` in production, or aborts on panic while the code relies on `catch_unwind`. judge reads the effective release profile and reports each one at the line that sets it.',
    tags: ['Release', 'Cargo'],
    specs: [
      { term: 'Rules', value: '`release-profile-hazard`, `panic-strategy-conflict`' },
      { term: 'Reads', value: 'Workspace `Cargo.toml` and `.cargo/config.toml`' },
      { term: 'Show it', value: '`cargo judge inspect`' },
    ],
    links: [{ label: 'Release profile rules', href: url('docs/reference/rules/#release-profile') }],
  },
];

export const tradeoffs: UseCasesPage['tradeoffs'] = {
  title: 'What judge does not do',
  items: [
    'It does not repeat the compiler or Clippy. Anything they already report is out of scope.',
    'It writes no patches. Refactoring candidates are ranked, the change stays yours.',
    'It reads no Git history and no authorship, only the tree as it is checked out.',
    'Heuristic findings are hints. They are listed, but never fail a verdict.',
  ],
};
