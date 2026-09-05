---
status: proposed
audience: architect
authoritative_for: why Kubernetes and observability platforms are not current
last_verified: 2026-09-06
---

# Deployment and observability (not implemented)

> **Not an approved phase.** This page is future reference architecture only.
> Do not present Kubernetes, Helm, Prometheus, OpenSearch, or similar as
> current SecureMail behavior. Current deployment is a workstation or
> single Linux host: uv, Node 22, Docker analyzer images, Uvicorn, and an
> optional worker process.

Health today is liveness only. There is no readiness probe that checks
Docker, disk quota, or the worker. There is no metrics exporter and no
central log pipeline.

A later deployment document would still pin analyzer images by digest and
keep `--network=none`. Container publish is **not** part of the current
[release process](../development/release-process.md).

Do not add `docker-compose` for a control plane without an approved phase.

## Related pages

- [Deployment topologies (current)](../operations/deployment-topologies.md)
- [Monitoring and health (current)](../operations/monitoring-and-health.md)
- [Compatibility matrix](../status/compatibility-matrix.md)

## Implementation anchors

- None for this proposal. Live health: `GET /api/v1/health`
