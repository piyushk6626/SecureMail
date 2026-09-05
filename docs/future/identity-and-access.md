---
status: proposed
audience: architect
authoritative_for: why identity providers are not current
last_verified: 2026-09-06
---

# Identity and access (not implemented)

> **Not an approved phase.** This page is future reference architecture only.
> Do not present OIDC, Keycloak, RBAC, or SSO as current SecureMail behavior.
> The live HTTP API has **no** authentication, authorization, or TLS
> termination. Bind to loopback on a trusted workstation.

`OIDC_ISSUER` is **not read**.

A later identity plane would wrap the existing routers. It must not move
policy evaluation, scoring, or ML into the identity provider. Analyst notes,
if persisted, remain a fourth UI region and never overwrite `Finding`
records.

Until that phase exists, treat local API exposure as a
[known limitation](../status/known-limitations.md).

## Related pages

- [API](../reference/api.md)
- [Current security limitations](../security/current-security-limitations.md)
- [Threat model](../security/threat-model.md)

## Implementation anchors

- None. Live code does not implement OIDC.
