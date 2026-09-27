// @ts-check
import casoonPages from '@casoon/pages-theme';
import { defineConfig } from 'astro/config';

// Project page: https://casoon.github.io/judge/ — `base` is the GitHub Pages path.
export default defineConfig({
  site: 'https://casoon.github.io/judge',
  base: '/judge/',
  integrations: [
    casoonPages({
      name: 'judge',
      description:
        'Deterministic post-refactoring analysis for Rust workspaces: evidence-backed findings, baselines and CI verdicts.',
      repo: 'casoon/judge',
      version: '0.7.0',
      license: 'BUSL-1.1',
      packages: [
        { label: 'crates.io', href: 'https://crates.io/crates/cargo-judge' },
        { label: 'docs.rs', href: 'https://docs.rs/cargo-judge' },
      ],
      docsGroups: {
        'getting-started': 'Getting started',
        guides: 'Guides',
        reference: 'Reference',
      },
    }),
  ],
});
