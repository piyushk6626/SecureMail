---
status: current
audience: architect
authoritative_for: mapping original OBJECTIVE deliverables to live proof
last_verified: 2026-09-06
---

# Requirements traceability

Original product text:
[`plans/requirements/OBJECTIVE.md`](../../plans/requirements/OBJECTIVE.md)
(`status: completed`). That file is provenance. It is not a license to add
PostgreSQL, queues, or OIDC.

This page maps each original deliverable to **Implemented** proof in this
repository, or to an explicit gap.

| Original deliverable | Status | Live proof |
|---|---|---|
| Passive analysis of SMTP/IMAP/POP3 from PCAP | **Implemented** | `securemail analyze`; 71 PCAP fixtures |
| Automatic protocol identification | **Implemented** | `port_hint` independent of `payload_evidence`; `pop3_nonstandard_port` |
| STARTTLS / STLS detection | **Implemented** | Per-protocol state machines; `imap_starttls_capability_stripped` |
| TCP stream reconstruction | **Implemented** | Quality classifier; `tcp_snaplen_truncation` never silent-complete |
| TLS handshake reconstruction | **Implemented** | `TlsHandshake`; `tls13_hello_retry_request` |
| Negotiated TLS version | **Implemented** | `supported_versions` wins over legacy record |
| Cipher suites | **Implemented** | IANA snapshot names/codes |
| Key exchange | **Implemented** | TLS 1.2 from suite grammar; TLS 1.3 from key_share/PSK |
| X.509 extraction | **Implemented** | Zeek DER; `cert_expired_rsa1024` (facts, not findings) |
| Certificate chain validation | **Implemented** | Offline snapshot; `cert_chain_san_mismatch` |
| Certificate expiration analysis | **Implemented** | Independent capture-time and analysis-time booleans |
| Public-key algorithm and length | **Implemented** | Plus effective-strength bits |
| Signature algorithm identification | **Implemented** | Cert signature ≠ handshake CertificateVerify |
| Deprecated protocols / weak suites | **Implemented** | Versioned YAML packs; Step 7 fixtures |
| Insecure protocol configurations | **Implemented** | Cleartext submission/access, LOGIN/PASS without TLS, upgrade violation |
| Forward secrecy assessment | **Implemented** | Present/absent/indeterminate; PSK-only is indeterminate |
| Prioritized findings | **Implemented** | `securemail.scoring/v1` + dedup |
| Cryptographic posture assessment | **Implemented** | Coverage denominators; unknown is not a pass |
| JSON / HTML / PDF reports | **Implemented** | `securemail report`; golden `securemail.report/v1` |
| Interactive dashboard | **Implemented** | FastAPI + React; Playwright `dashboard.spec.ts` |
| AI/ML cryptographic **risk classification** | **Known limitation** | Risk score is deterministic integer addends, not an ML classifier |
| AI-assisted anomaly detection | **Implemented** (advisory) | Baseline + gated Isolation Forest; never mutates findings |
| Mitigation recommendations | **Implemented** (pack `remediation_id`) | Not an LLM and not auto-applied to servers |
| Complete TCP reconstruction in all captures | **Known limitation** | Incomplete/conflicting quality is first-class; missing bytes are not invented |
| Revocation (OCSP/CRL) | **Known limitation** | Always `unknown` without imported artifacts |
| TLS 1.3 certificate visibility | **Known limitation** | `not_observable` unless history letter `x` |
| Multi-user SOC control plane | **Deferred** | See [future](../future/README.md) |

AI in the original objective is satisfied **only** as post-deterministic
advisory ML. An LLM is not a detector, compliance judge, or command executor.

## Related pages

- [Current capabilities](../status/current-capabilities.md)
- [Known limitations](../status/known-limitations.md)
- [Deferred scope](../status/deferred-scope.md)
- [Policy packs](policy-packs.md)

## Implementation anchors

- `plans/requirements/OBJECTIVE.md`
- `plans/completed/`
- `AGENTS.md` §1–2
