---
status: current
audience: operator
authoritative_for: loopback-only API, no auth, and analyzer isolation on one host
last_verified: 2026-09-06
---

# Security hardening

This build is a **single trusted workstation**. There is **no
authentication, authorization, or TLS termination**. Anyone who can reach
the HTTP port can upload captures, cancel jobs, and read catalog reports
(including OpenAPI at `/docs`).

Bind to loopback:

```bash
uv run uvicorn securemail.api.main:app --host 127.0.0.1 --port 8000
```

Do not publish `0.0.0.0`. Do not put this API behind a shared reverse proxy
expecting OIDC — `OIDC_ISSUER` is not read. **Deferred:** identity and
access.

## Process model

- Exactly one Uvicorn process. `--workers` greater than 1 is **unsafe**
  (`claim_next` is not compare-and-swap).
- Exactly one `python -m securemail.worker` (lifespan **or** standalone).
- Docker analyzers never run inside a FastAPI request.

## HTTP headers (all responses)

Implemented in `api/main.py` middleware:

- `Cache-Control: no-store`
- `Content-Security-Policy` (`default-src 'self'`, `object-src 'none'`,
  `frame-ancestors 'none'`, plus `base-uri 'self'` and `form-action 'self'`)
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-origin`
- `Referrer-Policy: no-referrer`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`

Vite dev proxy is same-machine only (`127.0.0.1:5173` → `127.0.0.1:8000`).

## Analyzer isolation

Every analyzer container gets the flags in `sandbox.py`: `--network=none`,
`--read-only`, user `65532:65532`, `--cap-drop=ALL`,
`--security-opt=no-new-privileges`, `--pids-limit=256`, 2 GiB memory/swap,
2 CPUs, 64 MiB `/tmp` tmpfs. Argv is a fixed `list[str]`; shell
metacharacters are rejected.

Captures bind-mount read-only. Originals are hashed before analyzers run.

**Known limitation:** the host Python worker is not network-namespaced.
WeasyPrint forbids non-`data:` URL fetches in PDF rendering. Jinja
autoescape stays on.

## Data handling

- Treat captures, banners, and certificate strings as hostile.
- Secret mail commands are redacted in protocol events.
- Do not log packet payloads, credentials, or private keys.
- Job paths never appear in API JSON.
- Catalog paths cannot escape the report root or use symlinks.

`SECUREMAIL_ANALYSIS_STUB=1` skips Docker. Never enable it on a host that
is supposed to isolate untrusted PCAPs.

## Quotas as abuse brakes

64 MiB uploads, 64 jobs, 2 GiB jobs+quarantine, 256 catalog reports. These
are local DoS brakes, not multi-tenant isolation.

## Related pages

- [Air-gapped operation](air-gapped-operation.md)
- [API reference](../reference/api.md)
- [Deployment topologies](deployment-topologies.md)
- [As-built analyzers](../architecture/analyzer-boundary.md)

## Implementation anchors

- `src/securemail/api/main.py`
- `src/securemail/adapters/analyzers/sandbox.py`
- `src/securemail/adapters/reports/pdf_renderer.py`

## Test evidence

- `tests/test_report_api.py`
- `tests/unit/test_analyzer_argv.py`
- `tests/unit/test_html_renderer.py`
- `tests/unit/test_pdf_renderer.py`
