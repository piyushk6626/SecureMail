---
status: current
audience: security
authoritative_for: analyzer Docker isolation flags and lockfile enforcement
last_verified: 2026-09-06
---

# Analyzer isolation

Packet ingest, TCP reassembly, protocol ID, TLS record decoding, and X.509
extraction happen in Zeek. TShark is a bounded second pass. Python never
builds analyzer commands through a shell.

Every analyzer container gets
[`sandbox_docker_flags()`](../../src/securemail/adapters/analyzers/sandbox.py):

| Flag | Value |
|---|---|
| `--network` | `none` |
| `--read-only` | set |
| `--user` | `65532:65532` |
| `--cap-drop` | `ALL` |
| `--security-opt` | `no-new-privileges` |
| `--pids-limit` | `256` |
| `--memory` / `--memory-swap` | `2g` |
| `--cpus` | `2` |
| `--tmpfs` | `/tmp:rw,nosuid,nodev,size=64m` |

Also `--rm`, capture bind-mounted **readonly** at `/data/capture.pcapng`,
output at `/data/out`. Timeout 120 s each. Combined output 50 MiB.

`assert_fixed_argv` rejects empty parts and the substrings ` && `, ` | `, `;`,
`$(`, backtick.

Do not silently continue if an analyzer image digest does not match
`analyzer-bundle.lock`.

TShark display filter (literal): `smtp or imap or pop or tls.handshake`.
Allowlisted fields only. Empty and non-mail captures do not start TShark
unless corroboration is required.

**Known limitation:** host Python (CLI, FastAPI, worker, WeasyPrint, sklearn)
is **not** net-sandboxed. Only analyzer containers use `--network=none`.
TShark is recipe-pinned, not content-pinned — see
[analyzer image upgrades](../development/analyzer-image-upgrades.md).

`SECUREMAIL_ANALYSIS_STUB=1` bypasses Docker. Tests and Playwright only.

## Related pages

- [Toolchain](../reference/toolchain.md)
- [Threat model](threat-model.md)
- [Decision 0001](../decisions/0001-imap-pop3-corroboration.md)

## Implementation anchors

- `src/securemail/adapters/analyzers/sandbox.py`
- `src/securemail/adapters/analyzers/zeek_runner.py`
- `src/securemail/adapters/analyzers/tshark_runner.py`
- `tools/analyzer-bundle.lock`

## Test evidence

- `tests/unit/test_analyzer_argv.py`
- `tests/unit/test_bundle_lock.py`
- `tests/test_capture_acceptance.py`
