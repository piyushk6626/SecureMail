---
status: proposed
audience: architect
authoritative_for: navigation for non-implemented future reference architecture
last_verified: 2026-09-06
---

# Future (not implemented)

> **Not an approved phase.** Pages in this directory are future reference
> architecture only. They do **not** describe the running product. Do not
> present PostgreSQL, Celery, OIDC, Kubernetes, or similar control-plane
> components as current SecureMail behavior. Current behavior is in
> [`docs/`](../README.md). Historical design under `plans/history/` is
> provenance, not a license to implement this directory.

This repository completed Steps 0–11 on a **single host**: CLI, sandboxed
analyzers, filesystem catalog, and a local worker process. Any scale-out
requires an explicitly approved contract after this documentation.

| Page | Topic |
|---|---|
| [Reference architecture](reference-architecture.md) | Logical components if a later phase exists |
| [Scale-out control plane](scale-out-control-plane.md) | Why Postgres/queues are not here |
| [Identity and access](identity-and-access.md) | Why OIDC/RBAC are not here |
| [Deployment and observability](deployment-and-observability.md) | Why K8s/metrics platforms are not here |
| [Migration triggers](migration-triggers.md) | Conditions that might justify a new phase |

## Invariants that must survive any later phase

These are live rules, not proposals:

1. **Deterministic-first findings** — ML never replaces, gates, suppresses,
   downgrades, or rewrites a `Finding`.
2. **Immutable evidence** — hash at intake; do not repair originals;
   competing reconstructions stay `conflicting`/`incomplete`.
3. **Analyzer `--network=none`** — no AIA/OCSP/CRL/CT/DNS/model fetch from
   an analysis worker.
4. **JSON authority** — HTML/PDF/UI render the same in-memory canonical
   object.
5. **Clean architecture** — `bootstrap.py` remains the only composition
   root; routers stay thin.

## Related pages

- [Current capabilities](../status/current-capabilities.md)
- [Deferred scope](../status/deferred-scope.md)
- [AGENTS.md](../../AGENTS.md)
