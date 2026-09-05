---
status: current
audience: architect
authoritative_for: filesystem catalog versus PostgreSQL
last_verified: 2026-09-06
---

# 0002. Filesystem catalog

Date: 2026-09-06 (retrospective)
Status: accepted
Step: 11 (dashboard catalog)

## Question

Should canonical reports be indexed in PostgreSQL (as sketched in historical
design) or in a bounded filesystem catalog the CLI and API already understand?

## Decision

Use a **filesystem catalog**: `catalog.json` plus `{case_id}.report.json`
under `SECUREMAIL_REPORT_ROOT`. Maximum **256** reports
(`DEFAULT_MAX_REPORT_COUNT`). Publication writes a temp file then
`os.replace`.

PostgreSQL, SQLAlchemy repositories, and Alembic remain **Deferred**. The
`api` extra still lists unused SQLAlchemy packages; they are not a live
control plane.

## Why

- Step 11 wraps the same JSON the CLI already produces. A database would
  duplicate the canonical object.
- Air-gapped and single-host operation does not need a database daemon.
- Path safety is enforceable with case-id regex, symlink checks, and size
  caps without an ORM.

## Consequences

- **Known limitation:** `CatalogPublisher.publish_report` docstring mentions
  fsync; `FilesystemCatalogPublisher` does **not** fsync after `os.replace`.
  A crash can lose the last catalog update.
- Replacing a `case_id` rewrites the report file and rewrites the whole
  catalog list. Concurrent publishers are unsafe.
- Catalog browse does not require the worker if
  `SECUREMAIL_START_WORKER=0`.

## Related pages

- [Known limitations](../status/known-limitations.md)
- [API](../reference/api.md)
- [Future scale-out](../future/scale-out-control-plane.md)

## Implementation anchors

- `src/securemail/adapters/persistence/writable_catalog.py`
- `src/securemail/adapters/persistence/report_repository.py`
- `src/securemail/ports/persistence.py`

## Test evidence

- `tests/unit/test_writable_catalog.py`
- `tests/unit/test_report_repository.py`
- `tests/test_report_api.py`
