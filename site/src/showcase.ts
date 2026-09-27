import { ansiToHtml } from '@casoon/pages-theme/ansi';
import type { ShowcaseExample } from '@casoon/pages-theme/showcase';

// Real judge 0.7.0 output, captured by running judge on its own source tree.
// examples/capture.sh regenerates every file; it only strips the absolute checkout path
// and terminal hyperlinks.
const files = import.meta.glob<string>('../../examples/*.{ansi,txt,md}', {
  query: '?raw',
  import: 'default',
  eager: true,
});

export function fixture(file: string): string {
  const source = files[`../../examples/${file}`];
  if (source === undefined) throw new Error(`Unknown fixture: ${file}`);
  return source;
}

const examples_ = [
  {
    slug: 'combined-report',
    title: 'Combined report',
    command: 'cargo judge --color always',
    file: 'summary.ansi',
    tags: ['tty', 'triage'],
    description:
      'The default run: every detector that needs no opt-in configuration, grouped by rule, with a representative location per group and the next commands to run.',
  },
  {
    slug: 'refactor-queue',
    title: 'Refactoring queue',
    command: 'cargo judge refactor',
    file: 'refactor.txt',
    tags: ['refactor', 'ranking'],
    description:
      'Files ranked by the evidence that points at them, with the rules behind each entry. judge ranks candidates; it never writes a patch.',
  },
  {
    slug: 'clone-families',
    title: 'Clone families',
    command: 'cargo judge dupes',
    file: 'dupes.txt',
    tags: ['dupes', 'duplication'],
    description:
      'Duplicated token spans grouped into families and ordered by repeated tokens, with every member location. Test-only code stays out unless you pass --include-tests.',
  },
  {
    slug: 'baseline-compare',
    title: 'Baseline compare',
    command: 'cargo judge compare .judge/baseline.json',
    file: 'compare.txt',
    tags: ['baseline', 'ci', 'verdict'],
    description:
      'The 0.7.0 tree compared with a baseline saved right after the source reorganisation (commit 8cfda89): resolved and introduced findings, and a verdict. A failing verdict exits with code 1, which is what a CI step checks.',
  },
  {
    slug: 'health-score',
    title: 'Health score',
    command: 'cargo judge health --score',
    file: 'health.txt',
    tags: ['health', 'complexity', 'score'],
    description:
      'Complexity ranking, slop signals and the health score with its basis: authored lines of code, failing and warning findings, and advisory findings that are not scored.',
  },
  {
    slug: 'workspace-map',
    title: 'Workspace map',
    command: 'cargo judge map',
    file: 'map.txt',
    tags: ['map', 'planning'],
    description:
      'Compact facts for a refactoring plan: files ordered by measured complexity and the largest clone families. Also available as versioned JSON.',
  },
  {
    slug: 'markdown-summary',
    title: 'Markdown summary',
    command: 'cargo judge --format markdown',
    file: 'summary.md',
    tags: ['markdown', 'review'],
    description:
      'The same grouped summary as Markdown, written to .judge/judge.md for a pull request description or an issue comment.',
  },
  {
    slug: 'explain-rule',
    title: 'Rule explanation',
    command: 'cargo judge explain-rule swallowed-result',
    file: 'explain-rule.txt',
    tags: ['rules', 'registry'],
    description:
      'A lookup in the static rule registry: evidence class, verdict effect, preconditions, exclusions and a curated example. It never runs an analysis.',
  },
];

export const examples: ShowcaseExample[] = examples_.map(({ file, command, ...meta }) => ({
  ...meta,
  file: `examples/${file}`,
  input: { code: command, lang: 'sh' },
  output: { html: ansiToHtml(fixture(file)), kind: 'terminal' },
}));
