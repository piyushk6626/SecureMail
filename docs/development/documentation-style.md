---
status: current
audience: contributor
authoritative_for: documentation metadata, page template, and writing rules
last_verified: 2026-09-06
---

# Documentation style

This page is the template for every Markdown file under `docs/` and for
`plans/README.md`. Historical plan bodies keep their original text; they still
carry the same YAML frontmatter.

## Frontmatter

Every page starts with:

```yaml
---
status: current
audience: operator
authoritative_for: short phrase naming the one fact this page owns
last_verified: 2026-09-06
---
```

| Field | Allowed values |
|---|---|
| `status` | `current`, `completed`, `historical`, `proposed` |
| `audience` | `user`, `operator`, `contributor`, `architect`, `security` |
| `authoritative_for` | one short phrase; other pages link here instead of repeating |
| `last_verified` | ISO date `YYYY-MM-DD` |

`status` meanings:

- `current` — describes live code, tests, or operator procedure
- `completed` — a finished contract kept as provenance
- `historical` — superseded design or scaffold; not live behavior
- `proposed` — not approved for implementation

## Authority

1. Executable code, fixtures, and tests describe **current behavior**.
2. `docs/` narrates that behavior.
3. [`AGENTS.md`](../../AGENTS.md) holds engineering constraints.
4. Completed plans under [`plans/completed/`](../../plans/completed/) are
   provenance.
5. [`plans/history/`](../../plans/history/) is not a license to add deferred
   infrastructure.
6. [`docs/future/`](../future/README.md) is explicitly non-implemented.

If this directory and a plan disagree on current behavior, source under `src/`,
`zeek/`, and `tests/` wins. Document the gap as a known limitation.

## One fact, one page

Landing pages summarize and link. Do not copy command tables, limit tables, or
environment-variable lists onto a second page. Point at:

- commands → [CLI reference](../reference/cli.md)
- HTTP routes → [API reference](../reference/api.md)
- environment variables → [environment variables](../reference/environment-variables.md)
- numeric limits → [limits](../reference/limits.md)
- pins → [toolchain](../reference/toolchain.md)

## Labels in body text

Use these words exactly when classifying a capability:

- **Implemented** — present in source and covered by a test or CLI proof
- **Known limitation** — present but weaker, non-atomic, or incomplete
- **Unsupported** — not validated (for example Windows)
- **Deferred** — named in historical design, not in this build
- **Future reference architecture** — guidance only, not an approved phase

## Commands

Use fenced `bash` blocks with the exact argv the repository runs. Prefer
`uv run …`. Do not invent throughput numbers, hardware SKUs, or commands that
are not in `Makefile`, Typer help, or source.

## Diagrams

Use Mermaid. Node IDs are camelCase with no spaces. Do not style colors.

## Closing sections

End topic pages with:

```markdown
## Related pages

## Implementation anchors

## Test evidence
```

Omit a section only when it would be empty.

## Maintenance

When code changes a command, route, limit, environment variable, or evidence
state, update the canonical reference page in the same change. Run
`make docs-check`. Do not regenerate PCAP fixtures as part of a documentation
edit.

## Related pages

- [Documentation hub](../README.md)
- [Documentation checker](make-targets.md)

## Implementation anchors

- `tools/check_docs.py`
- `docs/README.md`
