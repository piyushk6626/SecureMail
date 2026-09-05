---
status: current
audience: contributor
authoritative_for: when and how to refresh fixture expected.json
last_verified: 2026-09-06
---

# Golden updates

After changing Zeek scripts, `tools/analyzer-bundle.lock`, `_CONFIGURATION` in
`run_analysis.py`, or `trust-store-snapshot.pem`, golden `run_identity` values
change. Re-run:

```bash
uv run python tools/refresh_fixture_expected.py
# optional case filter:
uv run python tools/refresh_fixture_expected.py empty tls13_psk_only_resumption
```

The tool invokes the real CLI `analyze` for each PCAP fixture (default
`--analysis-time 2026-09-04T12:00:00Z` plus flags from `analyze.json`) and
overwrites `expected.json`. It does **not** edit `capture.pcapng`.

Prefer `uv run pytest` on the named `test_*_fixtures.py` file rather than
hand-diffing. Review the `expected.json` diff: only fields that are supposed
to change should move (digests, UIDs if the Zeek seed/script changed).

Do not regenerate PCAP fixtures as part of a documentation edit.

## Report golden

`tests/fixtures/reports/golden_report.json` is schema-first. Regenerate via
`tests/fixtures/reports/assemble.py` when models change, then update
`provenance.json` (JCS SHA-256, WeasyPrint version, font/template hashes,
page range currently 8–14; WeasyPrint 69.0 renders 11 pages). PDF bytes are
not goldened.

## Dashboard catalog

`tests/fixtures/dashboard/assemble.py` rebuilds committed catalog reports.
Playwright copies those JSON files into `out/e2e-data`.

## Frontend types

Schema changes also require:

```bash
npm --prefix frontend run generate:types
```

## Related pages

- [Fixture contract](fixture-contract.md)
- [Analyzer image upgrades](analyzer-image-upgrades.md)
- [Report development](report-development.md)

## Implementation anchors

- `tools/refresh_fixture_expected.py`
- `tests/fixtures/reports/assemble.py`
- `tests/fixtures/dashboard/assemble.py`

## Test evidence

- Fixture harness byte-equality after refresh
- `tests/unit/test_canonical_json.py` pinned JCS hash
