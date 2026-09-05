---
status: current
audience: operator
authoritative_for: live known limitations (not deferred future work)
last_verified: 2026-09-06
---

# Known limitations

These behaviors exist in source and are weaker, non-atomic, or incomplete.
They are not [deferred scope](deferred-scope.md) and not
[future reference architecture](../future/README.md).

## Control plane

| Limitation | Detail |
|---|---|
| Non-atomic job claim | `claim_next()` lists queued jobs then `update_job`. Not inter-process compare-and-swap. Multiple workers are unsafe. |
| Catalog no fsync | `FilesystemCatalogPublisher` uses `os.replace` on temp files. The `CatalogPublisher` protocol text mentions fsync; the adapter does not fsync. Crash can lose the last publish. Max **256** reports. |
| No retention API | Jobs and catalog files are deleted by the operator. `MAX_JOB_COUNT` (64) counts **all** job dirs, including completed — not a concurrent-job cap. |
| Stuck `running` jobs | Cancel is cooperative between stages and does not kill a running analyzer subprocess. A killed worker leaves status `running`. |
| Health liveness only | `GET /api/v1/health` is `{"status":"ok"}`. It does not check Docker, disk, worker, or catalog. |
| No authentication | Local API is fully capable for anyone who can connect. |
| Quota double-count | On commit, usage is jobs+quarantine **plus** the staged file size again. ML history and catalog reports are not fully included in the 2 GiB cap. Invalid `SECUREMAIL_MAX_CAPTURE_BYTES` is swallowed in `create_api()`. |

## Analyzers and host

| Limitation | Detail |
|---|---|
| TShark not content-pinned | Lock stores Dockerfile SHA-256. Runtime checks the tag exists and the recipe hash matches. Debian `tshark` package is unversioned. |
| Host Python not net-sandboxed | Only analyzer containers get `--network=none`. CLI, FastAPI, worker, WeasyPrint, and sklearn use the host network namespace. |
| Worker does not persist cert DER | CLI writes `<out-parent>/certificates/<sha256>.der`. Worker `_analyze_from_request` omits `artifact_root`. |

## Evidence and policy

| Limitation | Detail |
|---|---|
| ALPN implicit TLS on any port | Selected ALPN `smtp`/`imap`/`pop3` sets `implicit_tls.evidence_state=observed` regardless of responder port. Ports 465/993/995 without ALPN stay `indeterminate`. |
| TLS 1.3 certificates | Post-`ServerHello` certs are `not_observable` unless history letter `x` is present. Missing evidence is not a pass. |
| Revocation | Always `unknown` (no imported OCSP/CRL). |
| `verified` unused on classifiers | Reserved; findings use it as negative `evaluation_state`. |
| TShark well-known ports | IMAP/POP/SMTP dissectors bind well-known ports; nonstandard-port identity stays Zeek-only. |

## Dashboard and ML

| Limitation | Detail |
|---|---|
| Evidence resolver path mismatch | Engine `field_path` values are qualified (`handshake.version.selected`). The UI resolver walks paths relative to the record (`version.selected`). Live findings can resolve as `dangling_field`. Vitest fixtures use the relative form. |
| `AdvisoryItem` drops detector metadata | Only `code` and `reason` are stored. Detector name, endpoint, score, and contributions are discarded. |
| Analyst notes | Schema exists; the live UI does not persist notes. |
| Isolation Forest silence | Needs 40 local windows; baseline needs 14. |

## Packaging and architecture leakage

| Limitation | Detail |
|---|---|
| Unused SQLAlchemy extras | `api` extra lists SQLAlchemy, asyncpg, Alembic. Unused remnants. |
| API imports `ports` | Routers/CLI import `securemail.ports` for types and `MAX_REPORT_BYTES`. Import-linter allows it. |
| TShark output collection | `subprocess.run(capture_output=True)` then size check. Documented limits bound accepted data, not peak host allocation. |
| Analyze does not assemble reports | No CLI command wraps analyze JSON in `securemail.report/v1`. The worker calls `assemble_report`. |
| Working-copy hash | Report manifest `working_copy_availability` is `unavailable` on the CLI path. |

## Related pages

- [Current security limitations](../security/current-security-limitations.md)
- [Limits](../reference/limits.md)
- [Deferred scope](deferred-scope.md)
- [Decision 0002](../decisions/0002-filesystem-catalog.md)
- [Decision 0003](../decisions/0003-local-worker-model.md)

## Implementation anchors

- `src/securemail/adapters/persistence/job_store.py`
- `src/securemail/adapters/persistence/writable_catalog.py`
- `src/securemail/domain/policies/starttls/implicit_tls.py`
- `frontend/src/core/evidence_resolver.ts`
- `src/securemail/application/advisory_pipeline.py`

## Test evidence

- `tests/unit/test_job_store.py`
- `tests/unit/test_writable_catalog.py`
- `tests/unit/test_implicit_tls.py`
- `frontend/src/core/evidence_resolver.test.ts`
