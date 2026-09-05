---
status: current
audience: security
authoritative_for: current-build threat model
last_verified: 2026-09-06
---

# Threat model

Scope: a **single trusted workstation** running the CLI and/or the local
FastAPI + React dashboard. Analyzers are Linux containers. There is **no**
authentication. Bind the API to loopback.

This is not a Wireshark replacement, an active scanner, or a tool that
mutates mail-server config. The product does not break encryption or recover
plaintext without authorized key material.

## Assets

| Asset | Why it matters |
|---|---|
| Original capture bytes | Evidence; hashed at intake (`capture_sha256`) before analyzers |
| Working copy inside the sandbox | Must not write back to the original |
| Evidence JSON and canonical report | Forensic conclusions; JSON is authoritative |
| Extracted certificate DER | May contain names and public keys |
| Job store / catalog on disk | Local case material |
| Policy packs, IANA snapshot, trust store | Integrity of deterministic findings |
| Host Docker daemon | Analyzers run as containers on the same host |

## Adversaries

1. **Hostile capture** — malformed TCP, overlapping retransmissions, hostile
   banners (`<script>`, NUL, bidi overrides), truncated or nested ASN.1,
   unexpected STARTTLS sequences.
2. **Path traversal / catalog abuse** — crafted `case_id`, filenames, or
   symlinks under the data/report root.
3. **Local process on the workstation** — anyone who can reach the loopback
   API can upload captures, read reports, and cancel jobs.
4. **Compromised or drifting analyzer image** — digest mismatch or unpinned
   TShark packages.
5. **Docker-host privilege** — a breakout from an analyzer container is a
   host compromise. Controls reduce blast radius; they do not make Docker
   unprivileged.

## Controls (Implemented)

| Area | Control |
|---|---|
| Hostile captures | Reconstruction quality; evidence states; parser bounds |
| Redaction | Secret command arguments/text → `<redacted>` |
| Path traversal | Case/run id regex; symlink-safe catalog; store-root checks |
| Parser bounds | Rows, events, DER size/depth, pack size, report bytes |
| Sandbox | `--network=none`, `--read-only`, non-root `65532`, cap-drop, no-new-privileges, pids/memory/cpu, tmpfs |
| Offline PKI | Pinned PEM; no AIA/OCSP/CRL/CT/DNS fetch from an analysis worker |
| Report escaping | Jinja autoescape; `forensic_text`; `data:`-only PDF fetcher |
| Browser headers | `Cache-Control: no-store`, CSP, COOP/CORP, nosniff, DENY frames |
| Argv | Fixed lists; `assert_fixed_argv` rejects shell metacharacters |
| Intake hash | SHA-256 of the original file before analyzers |

## Out of scope for this build

OIDC/RBAC, TLS termination in-app, multi-tenant isolation, remote workers,
and signed reports (manifest `signature.availability` is `unavailable`).
See [future](../future/README.md) — **not an approved phase**.

## Related pages

- [Untrusted input handling](untrusted-input-handling.md)
- [Analyzer isolation](analyzer-isolation.md)
- [Current security limitations](current-security-limitations.md)

## Implementation anchors

- `src/securemail/adapters/analyzers/sandbox.py`
- `src/securemail/api/main.py`
- `src/securemail/adapters/reports/html_renderer.py`
- `src/securemail/adapters/persistence/report_repository.py`

## Test evidence

- `tests/unit/test_html_renderer.py` (hostile banner)
- `tests/unit/test_analyzer_argv.py`
- `tests/unit/test_report_repository.py` (traversal)
- `tests/unit/test_certificate_chain_fixtures.py` (no-inet guard)
