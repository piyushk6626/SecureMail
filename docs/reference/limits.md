---
status: current
audience: operator
authoritative_for: numeric bounds and resource caps
last_verified: 2026-09-06
---

# Limits

Values below are from source constants. They are not tuned from benchmarks.

## Capture jobs and catalog

| Limit | Value | Constant |
|---|---|---|
| Upload / capture size | 64 MiB | `MAX_CAPTURE_BYTES` (overridable via `SECUREMAIL_MAX_CAPTURE_BYTES`) |
| Job directories retained | 64 | `MAX_JOB_COUNT` — counts **all** job dirs, including completed |
| Data-root usage | 2 GiB | `MAX_DATA_ROOT_BYTES` — jobs + quarantine; ML history and root catalog reports are **not** fully included |
| Catalog reports | 256 | `DEFAULT_MAX_REPORT_COUNT` |
| Catalog index file | 1 MiB | `MAX_CATALOG_BYTES` |
| Original filename | 255 characters | `MAX_ORIGINAL_FILENAME_CHARS` |
| Canonical report JSON | 8 MiB | `MAX_REPORT_BYTES` |
| HTML artifact | 16 MiB | `MAX_HTML_BYTES` |
| PDF artifact | 32 MiB | `MAX_PDF_BYTES` |
| ML history windows | 512 | `MAX_ML_WINDOWS` |
| Score CLI input | 8 MiB | `MAX_SCORE_INPUT_BYTES` |

**Known limitation:** `max_jobs` is not a concurrent-job cap. Quota accounting
can double-count a staged upload during commit. See
[known limitations](../status/known-limitations.md).

## Analyzers

| Limit | Value | Constant |
|---|---|---|
| Analyzer timeout | 120 s each | `ANALYZER_TIMEOUT_SECONDS` |
| Combined analyzer output | 50 MiB | `MAX_OUTPUT_BYTES` |
| Certificate DER | 64 KiB each | `MAX_CERTIFICATE_DER_BYTES` |
| Certificates per run | 256 | `MAX_CERTIFICATES_PER_RUN` |
| ASN.1 constructed depth | 16 | `MAX_ASN1_DEPTH` |
| Chain depth | 16 | `MAX_CHAIN_DEPTH` |
| Container user | `65532:65532` | `SANDBOX_USER` |
| PIDs | 256 | `--pids-limit` |
| Memory / swap | 2 GiB / 2 GiB | `--memory`, `--memory-swap` |
| CPUs | 2 | `--cpus` |
| `/tmp` tmpfs | 64 MiB | `--tmpfs` |

Capinfos, Zeek, and optional TShark run **sequentially**. Worst-case analyzer
time approaches 360 seconds before report rendering. WeasyPrint and ML run in
the host worker and do **not** inherit Docker memory limits.

**Known limitation:** TShark uses `subprocess.run(capture_output=True)` and
checks size afterward. Zeek may `read_bytes()` a log before rejecting it.
Documented output limits bound accepted data, not peak host allocation during
collection.

## Normalization and policy

| Limit | Value |
|---|---|
| Zeek rows / TShark frames | 10 000 each |
| Events per session / flow | 256 |
| UID / fingerprint strings | 64 characters |
| Hostnames | 253 characters |
| Commands / tags | 32 characters |
| Event text | 128 characters |
| Policy pack file | 256 KiB |
| Rules per pack | 128 |
| Predicates per rule | 16 |
| Trust-store file | 2 MiB / 256 anchors |
| IANA snapshot | 1 MiB, 2048 ciphers, 512 groups |

## Worker

| Limit | Value |
|---|---|
| Poll interval | 0.5 s | `time.sleep(0.5)` in `run_capture_worker_loop` |
| Concurrency | one job at a time | single worker loop |
| Cancel | between stages | does not kill a running analyzer subprocess |

Multiple Uvicorn or worker processes are **unsafe**: `claim_next()` is not
inter-process compare-and-swap.

## Related pages

- [Resource limits (operator)](../operations/resource-limits.md)
- [Performance and tuning](../operations/performance-and-tuning.md)
- [Environment variables](environment-variables.md)

## Implementation anchors

- `src/securemail/domain/jobs/models.py`
- `src/securemail/adapters/analyzers/sandbox.py`
- `src/securemail/ports/persistence.py`
- `src/securemail/adapters/persistence/report_repository.py`

## Test evidence

- `tests/unit/test_capture_intake.py`
- `tests/unit/test_job_store.py`
- `tests/unit/test_report_repository.py`
- `tests/unit/test_analyzer_argv.py`
