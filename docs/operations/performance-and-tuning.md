---
status: current
audience: operator
authoritative_for: sequential analyzer timing and what cannot be tuned
last_verified: 2026-09-06
---

# Performance and tuning

This build has **no** published throughput numbers and **no** recommended
hardware SKUs. Do not invent either.

## What dominates wall time

Analyzers run one after another, not in parallel, each with a 120 s timeout
(`ANALYZER_TIMEOUT_SECONDS`):

1. capinfos (TShark image)
2. Zeek
3. TShark when the corroboration gate fires (mail, implicit-TLS ports 465/993/995,
   or any `ssl.log` UID)

Worst-case analyzer time approaches **360 seconds** before assemble, ML, and
render. Empty non-mail, non-TLS captures skip TShark.

The worker processes **one job at a time**. The loop sleeps 0.5 s when idle.
Uploads can sit `queued` behind a long Zeek/TShark run.

## Host work after Docker

PDF (WeasyPrint) and advisory ML run in the host worker process. They are
**unbounded** by Docker `--memory` / `--cpus`. Isolation Forest uses
`n_jobs=1`. There is no timeout constant around WeasyPrint or sklearn in this
code.

HTML must be ≤ 16 MiB and PDF ≤ 32 MiB or the job fails.

## What you can change

| Lever | Effect | Caveat |
|---|---|---|
| `SECUREMAIL_MAX_CAPTURE_BYTES` | Reject large uploads earlier | Invalid API values silently revert to 64 MiB |
| Do not run `--workers N` on Uvicorn | Correctness, not speed | Multiple processes corrupt claim |
| Exactly one worker | Correctness | Two workers race on `claim_next` |
| Catalog-only (`SECUREMAIL_START_WORKER=0`) | No analyzer load | Cannot upload |
| `SECUREMAIL_ANALYSIS_STUB=1` | Skips Docker | Tests/Playwright only; not real analysis |

You cannot raise analyzer timeouts, pids, or container memory without a code
change. Do not hand-edit `tools/analyzer-bundle.lock`.

## What you should not expect

- Concurrent capture pipelines
- Horizontal scale-out
- GPU acceleration
- Benchmarked jobs/hour
- Tuning flags for Zeek/TShark field lists (argv is fixed and allowlisted)

If jobs appear “stuck” under 360 s plus render time, wait or inspect
`status.json` `stage` before assuming a crash. See
[troubleshooting](troubleshooting.md).

## Related pages

- [Resource limits](resource-limits.md)
- [Limits](../reference/limits.md)
- [Job lifecycle](job-lifecycle.md)

## Implementation anchors

- `src/securemail/adapters/analyzers/sandbox.py`
- `src/securemail/bootstrap.py` (`run_capture_worker_loop`)
- `src/securemail/application/analysis_workflow.py`

## Test evidence

- `tests/unit/test_analyzer_argv.py`
- `tests/unit/test_analysis_workflow.py`
