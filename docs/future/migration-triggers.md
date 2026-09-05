---
status: proposed
audience: architect
authoritative_for: conditions that might justify a new approved phase
last_verified: 2026-09-06
---

# Migration triggers (not implemented)

> **Not an approved phase.** This page is future reference architecture only.
> Meeting a trigger does **not** authorize PostgreSQL, Celery, OIDC, or
> Kubernetes. It only suggests writing a new contract. Current product
> remains the single-host CLI and filesystem catalog.

Consider a **new** phase only if several of these are true **and** the
invariants in [future README](README.md) stay non-negotiable:

| Trigger | Current limitation it would address |
|---|---|
| More than one analysis worker is required | Non-atomic `claim_next`; not multi-process safe |
| Crash durability of the catalog is a forensic requirement | `os.replace` without fsync |
| Multiple analysts on a shared host/network | No auth; loopback assumption |
| Job retention must be policy, not operator `rm` | No retention API; stuck `running` jobs |
| Analyzer fleet must be scheduled across machines | Single Docker host |
| Signed reports / RFC 3161 required | Manifest signature `unavailable` |

Do **not** migrate because a design alternatives list mentioned a database.
Do not migrate to get a second ML model, an LLM judge, or Windows support.

When a phase is approved, update `AGENTS.md`, add completed-plan provenance,
and keep `docs/` as the as-built narrative.

## Related pages

- [Known limitations](../status/known-limitations.md)
- [Deferred scope](../status/deferred-scope.md)
- [Release process](../development/release-process.md)

## Implementation anchors

- None. Triggers are criteria, not code.
