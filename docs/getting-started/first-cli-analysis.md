---
status: current
audience: user
authoritative_for: first CLI analyze/score/report commands
last_verified: 2026-09-06
---

# First CLI analysis

Prerequisites: [macOS](macos-apple-silicon.md) or [Linux](linux.md) setup,
including analyzer images.

```bash
uv run securemail analyze tests/fixtures/empty/capture.pcapng --out out/empty.json
```

`--out` is required. Output is a v2 `EvidenceDocument` (pretty JSON). Extracted
certificates, if any, land in `out/certificates/<sha256>.der`.

The empty fixture has no mail sessions. A policy proof with TLS 1.3 PSK-only
resumption:

```bash
uv run securemail analyze \
  tests/fixtures/tls13_psk_only_resumption/capture.pcapng \
  --policy-profile ietf_current \
  --analysis-time 2026-09-04T12:00:00Z \
  --out out/policy.json
```

Scoring (synthetic findings, no PCAP):

```bash
uv run securemail score tests/fixtures/synthetic_findings/mixed_severity.json
```

Reports consume an already assembled `securemail.report/v1` object. Analyze
output is **not** that envelope. Use the committed golden for a first render:

```bash
uv run securemail report \
  tests/fixtures/reports/golden_report.json \
  --format json,html,pdf \
  --out out/
```

PDF needs the `reports` extra and Pango. The dashboard worker is the path that
assembles analyze output into a report after an upload. See
[generate reports](../user-guide/generate-reports.md).

Full option tables: [CLI reference](../reference/cli.md).

## Related pages

- [Analyze captures](../user-guide/analyze-captures.md)
- [Interpret evidence](../user-guide/interpret-evidence.md)
- [First dashboard run](first-dashboard-run.md)
