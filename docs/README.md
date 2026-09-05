---
status: current
audience: user
authoritative_for: documentation navigation and authority rules
last_verified: 2026-09-06
---

# SecureMail documentation

This directory describes **what the code does today**. Completed build-plan
contracts live under [`plans/`](../plans/README.md) as provenance. The
historical technical design is not the live architecture.

| Question | Go here |
|---|---|
| Current behavior | **this directory** |
| Engineering constraints | [`AGENTS.md`](../AGENTS.md) |
| Original requirements | [`plans/requirements/OBJECTIVE.md`](../plans/requirements/OBJECTIVE.md) |
| Completed step contracts | [`plans/completed/`](../plans/completed/) |
| Historical design / scaffold | [`plans/history/`](../plans/history/) |
| Non-implemented scale-out ideas | [`future/README.md`](future/README.md) |

If a page here and a plan disagree on live behavior, `src/`, `zeek/`, and
`tests/` win. Gaps are recorded as known limitations, not silently “fixed” in
prose.

Page template and metadata rules:
[documentation style](development/documentation-style.md).

## Start here

| Audience | First pages |
|---|---|
| New user | [Supported platforms](getting-started/supported-platforms.md) → [First CLI analysis](getting-started/first-cli-analysis.md) |
| Operator | [Deployment topologies](operations/deployment-topologies.md) → [API and worker startup](operations/api-and-worker-startup.md) |
| Contributor | [Workstation setup](development/workstation-setup.md) → [Testing](development/testing.md) |
| Architect | [System context](architecture/system-context.md) → [Analysis pipeline](architecture/analysis-pipeline.md) |
| Security reviewer | [Threat model](security/threat-model.md) → [Current security limitations](security/current-security-limitations.md) |

## Getting started

- [Index](getting-started/README.md)
- [Supported platforms](getting-started/supported-platforms.md)
- [macOS Apple Silicon](getting-started/macos-apple-silicon.md)
- [Linux](getting-started/linux.md)
- [First CLI analysis](getting-started/first-cli-analysis.md)
- [First dashboard run](getting-started/first-dashboard-run.md)
- [Offline installation](getting-started/offline-installation.md)

## User guide

- [Index](user-guide/README.md)
- [Analyze captures](user-guide/analyze-captures.md)
- [Policy profiles](user-guide/policy-profiles.md)
- [Interpret evidence](user-guide/interpret-evidence.md)
- [Interpret findings](user-guide/interpret-findings.md)
- [Scoring and coverage](user-guide/scoring-and-coverage.md)
- [Generate reports](user-guide/generate-reports.md)
- [Advisory ML](user-guide/advisory-ml.md)
- [Dashboard workflows](user-guide/dashboard-workflows.md)
- [Evidence limitations](user-guide/evidence-limitations.md)

## Architecture

- [Index](architecture/README.md)
- [System context](architecture/system-context.md)
- [Clean architecture](architecture/clean-architecture.md)
- [Runtime topology](architecture/runtime-topology.md)
- [Analysis pipeline](architecture/analysis-pipeline.md)
- [Analyzer boundary](architecture/analyzer-boundary.md)
- [Evidence and report contracts](architecture/evidence-and-report-contracts.md)
- [Filesystem control plane](architecture/filesystem-control-plane.md)
- [Worker lifecycle](architecture/worker-lifecycle.md)
- [Frontend data flow](architecture/frontend-data-flow.md)
- [Trust boundaries](architecture/trust-boundaries.md)

## Forensics

- [Index](forensics/README.md)
- [Capture intake](forensics/capture-intake.md)
- [TCP reconstruction](forensics/tcp-reconstruction.md)
- [Protocol identification](forensics/protocol-identification.md)
- [STARTTLS and STLS](forensics/starttls-and-stls.md)
- [Implicit TLS](forensics/implicit-tls.md)
- [TLS handshakes](forensics/tls-handshakes.md)
- [Certificate extraction](forensics/certificate-extraction.md)
- [Chain and identity validation](forensics/chain-and-identity-validation.md)
- [Policy evaluation](forensics/policy-evaluation.md)
- [Forward secrecy](forensics/forward-secrecy.md)
- [Finding deduplication](forensics/finding-deduplication.md)

## Operations

- [Index](operations/README.md)
- [Deployment topologies](operations/deployment-topologies.md)
- [Configuration](operations/configuration.md)
- [API and worker startup](operations/api-and-worker-startup.md)
- [Storage layout](operations/storage-layout.md)
- [Job lifecycle](operations/job-lifecycle.md)
- [Resource limits](operations/resource-limits.md)
- [Performance and tuning](operations/performance-and-tuning.md)
- [Retention and cleanup](operations/retention-and-cleanup.md)
- [Backup and recovery](operations/backup-and-recovery.md)
- [Monitoring and health](operations/monitoring-and-health.md)
- [Troubleshooting](operations/troubleshooting.md)
- [Air-gapped operation](operations/air-gapped-operation.md)
- [Security hardening](operations/security-hardening.md)

## Reference

- [Index](reference/README.md)
- [CLI](reference/cli.md)
- [API](reference/api.md)
- [Environment variables](reference/environment-variables.md)
- [Evidence schema](reference/evidence-schema.md)
- [Report schema](reference/report-schema.md)
- [Evidence states](reference/evidence-states.md)
- [Policy packs](reference/policy-packs.md)
- [Limits](reference/limits.md)
- [Exit codes and errors](reference/exit-codes-and-errors.md)
- [Toolchain](reference/toolchain.md)
- [Standards](reference/standards.md)
- [Glossary](reference/glossary.md)
- [Requirements traceability](reference/requirements-traceability.md)

## Development

- [Index](development/README.md)
- [Workstation setup](development/workstation-setup.md)
- [Repository map](development/repository-map.md)
- [Coding and import boundaries](development/coding-and-import-boundaries.md)
- [Make targets](development/make-targets.md)
- [Testing](development/testing.md)
- [Frontend development](development/frontend-development.md)
- [Fixture contract](development/fixture-contract.md)
- [Fixture generation](development/fixture-generation.md)
- [Golden updates](development/golden-updates.md)
- [Analyzer image upgrades](development/analyzer-image-upgrades.md)
- [Policy development](development/policy-development.md)
- [Report development](development/report-development.md)
- [ML evaluation](development/ml-evaluation.md)
- [CI](development/ci.md)
- [Release process](development/release-process.md)
- [Documentation style](development/documentation-style.md)

## Security

- [Index](security/README.md)
- [Threat model](security/threat-model.md)
- [Untrusted input handling](security/untrusted-input-handling.md)
- [Data handling and privacy](security/data-handling-and-privacy.md)
- [Analyzer isolation](security/analyzer-isolation.md)
- [Report rendering security](security/report-rendering-security.md)
- [Current security limitations](security/current-security-limitations.md)

## Status

- [Index](status/README.md)
- [Current capabilities](status/current-capabilities.md)
- [Compatibility matrix](status/compatibility-matrix.md)
- [Known limitations](status/known-limitations.md)
- [Deferred scope](status/deferred-scope.md)

## Future (not implemented)

- [Index](future/README.md)
- [Reference architecture](future/reference-architecture.md)
- [Scale-out control plane](future/scale-out-control-plane.md)
- [Identity and access](future/identity-and-access.md)
- [Deployment and observability](future/deployment-and-observability.md)
- [Migration triggers](future/migration-triggers.md)

## Decisions

- [Index](decisions/README.md)
- [0001 IMAP/POP3 corroboration](decisions/0001-imap-pop3-corroboration.md)
- [0002 Filesystem catalog](decisions/0002-filesystem-catalog.md)
- [0003 Local worker model](decisions/0003-local-worker-model.md)
- [0004 Evidence-state semantics](decisions/0004-evidence-state-semantics.md)

## Related pages

- [Root README](../README.md)
- [Plans index](../plans/README.md)
- [Contributing](../CONTRIBUTING.md)
