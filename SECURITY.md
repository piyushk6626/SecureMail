# Security

This project does **not** currently publish a dedicated vulnerability-reporting
mailbox, PGP key, or bug-bounty program. That contact is a project-owner
decision that has not been recorded in this repository. Until one exists, do
not assume inbound GitHub issues are a private channel.

## Current threat boundary

SecureMail analyzes **hostile** PCAP/PCAPNG files on a **single trusted
workstation**.

- Analyzer containers run `--network=none`, read-only, non-root `65532`,
  dropped capabilities, and fixed resource limits.
- The host Python CLI, FastAPI process, and worker are **not** OS-network
  sandboxed.
- The HTTP API has **no authentication**. Bind it to loopback. Do not expose
  it on a network.
- There is no TLS termination, multi-tenant isolation, signed offline bundle,
  SBOM, or dependency/container scanning in this build.

Details: [threat model](docs/security/threat-model.md),
[current security limitations](docs/security/current-security-limitations.md),
[hardening](docs/operations/security-hardening.md).

## Handling captures and artifacts

Treat captures, decoded banners, certificate strings, and report fields as
hostile. Do not log packet payloads, credentials, or private keys. See
[data handling](docs/security/data-handling-and-privacy.md).

## Analyzer digest mismatches

Do not silently continue if Zeek bundle/image labels disagree with
`tools/analyzer-bundle.lock`. TShark verification is weaker (Dockerfile hash
plus image-tag presence); see [known limitations](docs/status/known-limitations.md).
