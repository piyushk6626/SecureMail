---
status: proposed
audience: architect
authoritative_for: why a queued multi-worker control plane is not current
last_verified: 2026-09-06
---

# Scale-out control plane (not implemented)

> **Not an approved phase.** This page is future reference architecture only.
> Do not present PostgreSQL, Celery, RabbitMQ, Redis, or similar as current
> SecureMail behavior. Current jobs use a bounded filesystem store and a
> single local worker. See [decision 0003](../decisions/0003-local-worker-model.md).

A later phase **might** introduce durable job rows, compare-and-swap claims,
and more than one analysis worker. That is not approved. The live claim path
is non-atomic and **not multi-process safe**.

If such a phase is ever written, it must preserve:

- Deterministic-first findings
- Immutable evidence (intake hash, no original mutation)
- Analyzer `--network=none`
- JSON authority
- Clean architecture (`application/` does not import Celery or SQLAlchemy)

Do not run Zeek inside a FastAPI request. The current worker already keeps
analyzers out of the request path; scale-out must not reverse that.

`DATABASE_URL` in older notes is **not read**. Unused SQLAlchemy extras in
the `api` optional dependency are remnants, not a hidden ORM.

## Related pages

- [Filesystem catalog decision](../decisions/0002-filesystem-catalog.md)
- [Local worker decision](../decisions/0003-local-worker-model.md)
- [Known limitations](../status/known-limitations.md)

## Implementation anchors

- None for this proposal. Live code: `src/securemail/adapters/persistence/`
