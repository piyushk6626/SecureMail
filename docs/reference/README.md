---
status: current
audience: user
authoritative_for: reference navigation
last_verified: 2026-09-06
---

# Reference

Machine-facing facts for the live SecureMail CLI, HTTP API, schemas, packs,
pins, and vocabulary. Command tables, route tables, environment-variable lists,
numeric limits, and toolchain pins live on **one** page each. Other pages link
here instead of copying those tables.

## Commands and runtime

| Page | Owns |
|---|---|
| [CLI](cli.md) | `analyze`, `score`, `report`, `evaluate-ml` argv and examples |
| [HTTP API](api.md) | Routes, status codes, request shapes |
| [Environment variables](environment-variables.md) | Live `SECUREMAIL_*` / Vite variables |
| [Limits](limits.md) | Numeric bounds from source constants |
| [Exit codes and errors](exit-codes-and-errors.md) | Process exits and exception types |
| [Toolchain](toolchain.md) | Pinned Python, Node, Zeek, extras |

## Contracts

| Page | Owns |
|---|---|
| [Evidence schema](evidence-schema.md) | `securemail.evidence/v2` envelope |
| [Report schema](report-schema.md) | `securemail.report/v1` envelope |
| [Evidence states](evidence-states.md) | The seven `EvidenceState` values |
| [Policy packs](policy-packs.md) | Built-in YAML rule ids and clocks |

## Vocabulary and provenance

| Page | Owns |
|---|---|
| [Standards](standards.md) | RFCs and NIST documents the packs cite |
| [Glossary](glossary.md) | Product terms used in docs and JSON |
| [Requirements traceability](requirements-traceability.md) | Original objective → live proof |

## Related pages

- [Documentation hub](../README.md)
- [Current capabilities](../status/current-capabilities.md)
- [Documentation style](../development/documentation-style.md)
