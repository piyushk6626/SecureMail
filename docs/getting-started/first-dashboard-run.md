---
status: current
audience: user
authoritative_for: first local dashboard startup
last_verified: 2026-09-06
---

# First dashboard run

The dashboard is FastAPI plus a React UI on one trusted workstation. It can
browse a catalog and upload PCAP/PCAPNG files. Packet decoding still happens
in sandboxed Zeek/TShark, never in the browser.

There is **no login**. Bind to loopback.

## Analyze on this host

```bash
SECUREMAIL_DATA_ROOT=out/data \
SECUREMAIL_REPORT_ROOT=out/data \
SECUREMAIL_START_WORKER=1 \
  uv run uvicorn securemail.api.main:app --reload
```

In another terminal:

```bash
npm --prefix frontend run dev
```

Vite listens on `127.0.0.1:5173` and proxies `/api` to `127.0.0.1:8000`.

Upload a `.pcap` / `.pcapng` from the UI. Polling uses
`GET /api/v1/analyses/{run_id}`. When `status` is `completed`, JSON/HTML/PDF
downloads are available.

Until 14 local endpoint-windows exist, Advisory / ML shows
`ADVISORY_INSUFFICIENT_HISTORY` rather than implying a clean baseline.

## Catalog only

```bash
SECUREMAIL_REPORT_ROOT=tests/fixtures/dashboard \
SECUREMAIL_START_WORKER=0 \
  uv run uvicorn securemail.api.main:app --reload
```

Omitting `SECUREMAIL_START_WORKER=0` while a root is set **starts the worker**.

After `make frontend-build`, FastAPI serves `frontend/dist` from the same
Uvicorn process.

## Related pages

- [Dashboard workflows](../user-guide/dashboard-workflows.md)
- [API and worker startup](../operations/api-and-worker-startup.md)
- [Environment variables](../reference/environment-variables.md)
- [API reference](../reference/api.md)
