---
status: current
audience: operator
authoritative_for: operations documentation navigation
last_verified: 2026-09-06
---

# Operations

Operator procedures for a **single trusted workstation**. There is no
multi-node control plane, no authentication, and no deletion API in this
build.

Numeric caps: [limits](../reference/limits.md). Environment variables:
[environment-variables](../reference/environment-variables.md). HTTP routes:
[API reference](../reference/api.md).

## Start here

1. [Deployment topologies](deployment-topologies.md) — CLI-only, catalog-only,
   or analysis workstation.
2. [Configuration](configuration.md) — what is actually read.
3. [API and worker startup](api-and-worker-startup.md) — one Uvicorn, one
   worker.
4. [Storage layout](storage-layout.md) — jobs, quarantine, catalog, ML
   history.
5. [Job lifecycle](job-lifecycle.md) — states, cancel, duplicates.
6. [Resource limits](resource-limits.md) — quotas and analyzer sandbox.
7. [Performance and tuning](performance-and-tuning.md) — sequential 120 s
   analyzers; no invented throughput.
8. [Retention and cleanup](retention-and-cleanup.md) — manual `jobs/` deletion.
9. [Backup and recovery](backup-and-recovery.md)
10. [Monitoring and health](monitoring-and-health.md) — `/health` is liveness.
11. [Troubleshooting](troubleshooting.md) — runbooks.
12. [Air-gapped operation](air-gapped-operation.md)
13. [Security hardening](security-hardening.md)

## Related pages

- [First dashboard run](../getting-started/first-dashboard-run.md)
- [Offline installation](../getting-started/offline-installation.md)
- [User guide](../user-guide/README.md)
- [Environment variables](../reference/environment-variables.md)
- [Limits](../reference/limits.md)
- [API reference](../reference/api.md)

## Implementation anchors

- `src/securemail/api/main.py`
- `src/securemail/worker.py`
- `src/securemail/bootstrap.py`

## Test evidence

- `tests/test_analysis_api.py`
- `tests/test_capture_acceptance.py`
- `tests/unit/test_job_store.py`
