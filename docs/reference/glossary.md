---
status: current
audience: user
authoritative_for: product glossary
last_verified: 2026-09-06
---

# Glossary

Terms used in JSON, CLI, and these docs. Prefer the live schema pages when a
field name is in dispute.

| Term | Meaning |
|---|---|
| Analyze | CLI command that turns a PCAP/PCAPNG into `securemail.evidence/v2`. |
| Advisory / ML | Shadow-mode anomaly section. Never a `Finding`. Off by default on `report`. |
| Analyzer bundle | `tools/analyzer-bundle.lock` plus the hashed `zeek/` tree and TShark Dockerfile hash. |
| Assessment state | Posture coverage class: `complete`, `limited`, or `none`. |
| Basis state | Weakest `EvidenceState` among a finding’s evidence references. |
| Canonical report | `securemail.report/v1` object. JSON is authoritative. |
| Capinfos | TShark-image preflight that records packet counts and snaplen before Zeek. |
| Catalog | Bounded filesystem index `catalog.json` plus `{case_id}.report.json` files. Max 256 reports. |
| Case id | Catalog key, 1–160 chars matching `^[A-Za-z0-9][A-Za-z0-9._-]*$`. |
| Configuration digest | Hash of analysis config plus IANA snapshot and optional hostname. Excludes the policy pack. |
| Corroboration | `zeek` or `zeek+tshark`. TShark never owns protocol identity. |
| Coverage denominators | `passed` / `failed` / `unknown` / `not_observable` counts. Unknown is not a pass. |
| Data root | `SECUREMAIL_DATA_ROOT`: jobs, quarantine, artifacts, ML history. |
| Dedup | Collapse session findings to one endpoint finding without dropping session references. |
| Deterministic finding | YAML rule outcome (`negative` or `indeterminate`). Independent of ML. |
| `downgrade_consistent` | STARTTLS/STLS accepted after a stripped advertisement. Not proof of an attacker. |
| Evidence state | One of seven visibility values. See [evidence states](evidence-states.md). |
| Explicit upgrade | STARTTLS (SMTP/IMAP) or STLS (POP3) state machine. |
| Fixture | `tests/fixtures/<case_id>/` capture + `expected.json` + `provenance.json`. |
| Forward secrecy | Version-aware present/absent/indeterminate from key exchange. Never infers ticket rotation. |
| Historical pack | `historical_at_capture`; evaluation clock is capture start time. |
| Idempotency key | Digest tuple identifying one analysis of one capture. Not a stored field. |
| Implicit TLS | Mail-over-TLS correlation from selected ALPN, not from port number. |
| Isolation Forest | Gated challenger detector. Silent until 40 local endpoint-windows. |
| JCS | RFC 8785 JSON Canonicalization Scheme used for `report.json`. |
| Job | Filesystem analysis record: queued → running → completed/failed/cancelled. |
| Normalization schema | `"v1"` facts. Document schema `"v2"` adds findings/posture. |
| `not_observable` | Fact cannot be seen (including TLS 1.3 hidden certificates). Not a pass. |
| Payload evidence | Protocol from bytes/DPD. Independent of `port_hint`. |
| Policy check | Applicable pass/fail/unknown/not-observable evaluation retained for coverage. |
| Policy pack | Versioned YAML under `domain/policies/rules/`. |
| Port hint | Well-known port guess. Never proof of protocol. |
| Posture | Endpoint-deduped findings plus coverage (`securemail.posture/v1`). |
| Provenance | `provenance.json` recording how a fixture capture was made. |
| Report root | `SECUREMAIL_REPORT_ROOT`: published catalog. |
| Risk score | Max endpoint priority 0–100, or `null` when coverage is `none`/`limited` and there are no findings. |
| Run id | Analysis job identifier. |
| Scoring | `securemail.scoring/v1` integer addends. Transparent priority, not a universal risk percentage. |
| Snaplen | Capture snapshot length. Truncation is `incomplete`, never silently `complete`. |
| Stub analysis | `SECUREMAIL_ANALYSIS_STUB=1` bypasses Docker. Tests and Playwright only. |
| Trust store | Pinned offline PEM snapshot. No AIA/OCSP/CRL fetch. |
| Worker | Out-of-process `python -m securemail.worker` loop. Not Celery. |
| Zeek UID | Connection id stable given `redef global_hash_seed = "securemail-v0"`. |

## Related pages

- [Evidence schema](evidence-schema.md)
- [Report schema](report-schema.md)
- [CLI](cli.md)

## Implementation anchors

- `src/securemail/domain/evidence/run.py`
- `src/securemail/domain/reports/schema.py`
