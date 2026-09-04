# SecureMail as-built documentation

This directory describes **what the code does today**, not the full product
vision. The live surface is a CLI that reads a PCAP/PCAPNG and writes a v0
`EvidenceDocument` JSON file.

Current implementation: **Steps 0–6** of
[`plans/build_plan.md`](../plans/build_plan.md) (foundations, TCP reconstruction,
SMTP/IMAP/POP3 identification, STARTTLS/STLS and implicit TLS, TLS handshake
version/cipher/key exchange, certificate facts, chain validation and identity).
Steps 7–11 are named placeholders only.

## How these docs relate to the rest of the repo

| Location | Role |
|---|---|
| **this directory** | As-built: pipeline, schema, analyzers, fixtures as they exist in source |
| [`plans/TECHNICAL_DESIGN.md`](../plans/TECHNICAL_DESIGN.md) | What to build and why (full architecture, including later steps) |
| [`plans/build_plan.md`](../plans/build_plan.md) | Order of work and the test that proves each step |
| [`plans/PROJECT_SCAFFOLD.md`](../plans/PROJECT_SCAFFOLD.md) | File layout, toolchain, import boundaries |
| [`plans/OBJECTIVE.MD`](../plans/OBJECTIVE.MD) | Product requirements / deliverable list |
| [`AGENTS.md`](../AGENTS.md) | Standing brief for agents working in this repository |
| [`README.md`](../README.md) | Bootstrap and a short pointer here |

Do not treat a placeholder file (`"""Filled in at Step N."""`) as implemented
behavior. If this directory and a plan disagree on *current* behavior, the
source under `src/`, `zeek/`, and `tests/fixtures/` wins.

## Contents

| Page | What it covers |
|---|---|
| [current-state.md](current-state.md) | Done vs not done, proof commands, fixture count |
| [architecture.md](architecture.md) | Layers, import-linter, composition root, live modules |
| [pipeline.md](pipeline.md) | `securemail analyze` end to end, digests, idempotency |
| [evidence-model.md](evidence-model.md) | v0 JSON envelope, `EvidenceState`, `Flow`, `EmailSession`, `TlsHandshake` |
| [analyzers.md](analyzers.md) | Sandbox, lockfile, Zeek scripts, TShark allowlist, redaction |
| [tcp-reconstruction.md](tcp-reconstruction.md) | Quality classifier, reason codes, `sm_tcp_recon.log` |
| [protocol-identification.md](protocol-identification.md) | `port_hint` vs payload, DPD, corroboration, conflict |
| [starttls.md](starttls.md) | STARTTLS/STLS machines, `downgrade_consistent`, implicit TLS |
| [cli-and-development.md](cli-and-development.md) | CLI, Make targets, doctor, lint, CI |
| [fixtures.md](fixtures.md) | Catalog of the 64 committed cases |
| [decisions/step2-imap-pop3-depth.md](decisions/step2-imap-pop3-depth.md) | ADR: Zeek vs TShark vs Spicy for IMAP/POP3 |

## Quick start

```bash
uv run securemail analyze tests/fixtures/empty/capture.pcapng --out out/empty.json
```

The only registered command is `analyze`. See
[cli-and-development.md](cli-and-development.md) for toolchain and
[current-state.md](current-state.md) for the proof command of each completed
step.
