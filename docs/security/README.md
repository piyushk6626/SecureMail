---
status: current
audience: security
authoritative_for: security documentation navigation
last_verified: 2026-09-06
---

# Security

SecureMail treats captures, banners, certificates, and report fields as
**hostile**. Packet decoding runs in network-disabled analyzer containers.
Host Python orchestrates, scores, and renders; it is not net-sandboxed.

| Page | Owns |
|---|---|
| [Threat model](threat-model.md) | Assets, adversaries, and controls |
| [Untrusted input handling](untrusted-input-handling.md) | PCAP, JSON, YAML, ASN.1 bounds |
| [Data handling and privacy](data-handling-and-privacy.md) | Hashing, redaction, no payload logs |
| [Analyzer isolation](analyzer-isolation.md) | Docker flags and lockfile |
| [Report rendering security](report-rendering-security.md) | Escape, fonts, PDF fetcher, headers |
| [Current security limitations](current-security-limitations.md) | Auth, worker, catalog, host Python |

## Related pages

- [Known limitations](../status/known-limitations.md)
- [Operations — security hardening](../operations/security-hardening.md)
- [Trust boundaries](../architecture/trust-boundaries.md)
