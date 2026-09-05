---
status: current
audience: contributor
authoritative_for: how fixture captures are generated and what must not be rewritten
last_verified: 2026-09-06
---

# Fixture generation

Generator scripts live in
[`tests/fixtures/generators/`](../../tests/fixtures/generators/).
`make test` ignores that directory (`--ignore=tests/fixtures/generators`).

**Do not rewrite a generator in place** once a fixture’s `provenance.json`
points at it. Change means a new script or a new fixture. Do not edit
`capture.pcapng` after creation. Binary captures use **git-lfs**
(`*.pcap`, `*.pcapng`, `*.der`, `*.p12`, `*.pfx`). JSON stays ordinary git text.

## Lab captures on macOS

Docker Desktop runs containers inside a Linux VM. Host `tcpdump` on `en0` only
sees the VM uplink, never container-to-container traffic.

1. Create a user-defined Docker bridge network.
2. Attach the mail-server containers to that network.
3. Attach a tcpdump/dumpcap sidecar to the **same** network with
   `--cap-add=NET_RAW --cap-add=NET_ADMIN`.
4. Capture on the bridge (or `--network container:<server>`), not on the
   macOS host.

Details: [`tests/fixtures/generators/README.md`](../../tests/fixtures/generators/README.md).

## Public corpus

Import scripts pin the upstream URL and **source SHA-256**, then convert with
`editcap -F pcapng` (or equivalent) **without otherwise altering packets**.
After the bytes are hashed, conversion is local. These traces are regression
only; they are never the sole proof of a rule.

## Legacy OpenSSL

Static RSA, static ECDH, RC4, TLS 1.0/1.1, NULL, export, SHA-1
CertificateVerify, and RSA-1536 lab cases use a pinned **OpenSSL 1.0.2u**
image (`legacy_openssl.Dockerfile`). Do not rewrite
`lab_legacy_openssl_captures.py` for Step 7; `lab_policy_boundary_captures.py`
is the later script.

## Generator index

| Script | Cases |
|---|---|
| `empty_capture.py` | `empty` |
| `tcp_degradation_captures.py` | TCP degradation / reorder / duplicate |
| `lab_smtp_tcp_baseline.py` | `tcp_smtp_clean_baseline` |
| `lab_mail_protocol_captures.py` | SMTP/587, IMAP/143, POP3/110 |
| `scapy_protocol_captures.py` | Nonstandard ports, ambiguous banner |
| `import_public_corpus.py` | Public SMTP/IMAP and STARTTLS/STLS slices |
| `lab_starttls_captures.py` | Successful STARTTLS/STLS, implicit TLS, TLS-on-port without ALPN |
| `scapy_starttls_captures.py` | Reject, strip, violation, plaintext credentials |
| `lab_tls_handshake_captures.py` | TLS 1.2 ECDHE, TLS 1.3 full, HelloRetryRequest, PSK-only resumption |
| `lab_legacy_openssl_captures.py` | TLS 1.2 static RSA, static ECDH, RC4 via OpenSSL 1.0.2u |
| `scapy_tls_edge_captures.py` | `supported_versions` vs legacy record; truncated ClientHello |
| `import_tls_public_corpus.py` | Independent TLS 1.2 / TLS 1.3 regression slices |
| `lab_cert_captures.py` | Step 5 lab certificate-matrix captures |
| `scapy_cert_malformed_captures.py` | Malformed Certificate message |
| `import_cert_public_corpus.py` | Independent full-chain TLS 1.2 public-corpus slice |
| `lab_chain_captures.py` | Step 6 lab CA chain, self-signed, missing intermediate, SAN match/mismatch |
| `lab_policy_boundary_captures.py` | Step 7 lab TLS 1.0/1.1, NULL/export, SHA-1 CertificateVerify, RSA-1536 |
| `scapy_policy_boundary_captures.py` | Step 7 Scapy TLS 1.2 static DH ServerHello |
| `step8_synthetic_findings.py` | Step 8 scoring/dedup/coverage JSON sets |

SMTP on TCP/25 reuses the immutable Step 1 capture
`tcp_smtp_clean_baseline`. Advertised-but-never-requested STARTTLS reuses the
Step 2 `*_nonstandard_port` Scapy fixtures.

Private keys for lab CAs stay in the generator. The lab root **public**
certificate is pinned in `src/securemail/adapters/pki/trust-store-snapshot.pem`.

## Related pages

- [Fixture contract](fixture-contract.md)
- [Golden updates](golden-updates.md)
- [Untrusted input handling](../security/untrusted-input-handling.md)

## Implementation anchors

- `tests/fixtures/generators/`
- `tests/fixtures/generators/README.md`

## Test evidence

- Each fixture `provenance.json` names the generator path and capture SHA-256
