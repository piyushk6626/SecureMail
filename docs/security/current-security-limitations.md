---
status: current
audience: security
authoritative_for: security-relevant known limitations in this build
last_verified: 2026-09-06
---

# Current security limitations

These are **Known limitation** items in the live tree. They are not future
architecture. Product and operational gaps that are not primarily security
controls are listed on [known limitations](../status/known-limitations.md).

| Limitation | What exists instead |
|---|---|
| **No authentication, authorization, or TLS termination** | Bind loopback on a trusted workstation |
| **Health is liveness only** | `GET /api/v1/health` returns `{"status":"ok"}` without checking Docker, disk, worker, or catalog |
| **Host Python is not net-sandboxed** | Only Zeek/TShark containers use `--network=none` |
| **TShark not content-pinned** | Lock hashes Dockerfile bytes; `apt-get install tshark` is unversioned |
| **Non-atomic job claim** | `claim_next()` lists queued jobs then `update_job`; not compare-and-swap. Multiple Uvicorn/worker processes are unsafe |
| **Catalog `os.replace` without fsync** | Protocol docstring mentions fsync; `FilesystemCatalogPublisher` does not fsync |
| **No retention API** | Operators delete job/catalog files by hand |
| **Stuck `running` jobs** | Cancel is cooperative between stages and does not kill a running analyzer. A dead worker leaves `running` |
| **Worker does not persist cert DER** | CLI writes `<out>/certificates/<sha256>.der`; worker `artifact_root` is unset |
| **Local API exposure** | Anyone who can reach the port can upload and read |
| **Docker-host privilege** | Analyzer breakout is a host issue; flags reduce caps and network, they do not remove the daemon |
| **Unused SQLAlchemy extras** | `api` extra installs SQLAlchemy/asyncpg/Alembic that are not used — extra attack surface in the venv, not a live DB |

`DATABASE_URL` and `OIDC_ISSUER` are **not read**.

## Related pages

- [Threat model](threat-model.md)
- [Known limitations](../status/known-limitations.md)
- [Decision 0002](../decisions/0002-filesystem-catalog.md)
- [Decision 0003](../decisions/0003-local-worker-model.md)

## Implementation anchors

- `src/securemail/adapters/persistence/job_store.py`
- `src/securemail/adapters/persistence/writable_catalog.py`
- `src/securemail/bootstrap.py`
- `src/securemail/api/routers/reports.py`

## Test evidence

- `tests/unit/test_job_store.py`
- `tests/unit/test_writable_catalog.py`
- `tests/test_analysis_api.py`
