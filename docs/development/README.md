---
status: current
audience: contributor
authoritative_for: contributor documentation navigation
last_verified: 2026-09-06
---

# Development

Contributor procedures for the live tree. Install steps for a new operator
workstation stay in [getting started](../getting-started/README.md). This
section assumes those pins and adds the map, tests, fixtures, and release
checklist.

| Page | Owns |
|---|---|
| [Workstation setup](workstation-setup.md) | Extra contributor tools; links install pages |
| [Repository map](repository-map.md) | Where files live |
| [Coding and import boundaries](coding-and-import-boundaries.md) | Clean-architecture import rules |
| [Make targets](make-targets.md) | Makefile recipes |
| [Testing](testing.md) | Pytest / Vitest / Playwright inventory |
| [Frontend development](frontend-development.md) | Node 22, types, Vite |
| [Fixture contract](fixture-contract.md) | Directory shape and catalog tables |
| [Fixture generation](fixture-generation.md) | Lab / Scapy / public corpus rules |
| [Golden updates](golden-updates.md) | When to refresh `expected.json` |
| [Analyzer image upgrades](analyzer-image-upgrades.md) | Lockfile + image rebuild |
| [Policy development](policy-development.md) | YAML packs |
| [Report development](report-development.md) | Schema, template, JCS |
| [ML evaluation](ml-evaluation.md) | Cohort gates |
| [CI](ci.md) | GitHub Actions jobs |
| [Release process](release-process.md) | What this repo does **not** publish |
| [Documentation style](documentation-style.md) | Frontmatter and writing rules |

## Related pages

- [Documentation hub](../README.md)
- [AGENTS.md](../../AGENTS.md)
- [Toolchain](../reference/toolchain.md)
