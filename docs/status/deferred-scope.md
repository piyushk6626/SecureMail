---
status: current
audience: architect
authoritative_for: named design items not present in this build
last_verified: 2026-09-06
---

# Deferred scope

**Deferred** means named in historical design or `AGENTS.md` “what not to do”,
and **not** implemented. It is not an approved next phase. Ideas that would
require a new contract live under [future](../future/README.md) with
`status: proposed`.

Do not add these because they appear on an alternatives list:

| Item | Notes |
|---|---|
| PostgreSQL / SQLAlchemy repositories | Catalog is filesystem JSON |
| RabbitMQ / Celery / Redis queues | Worker is a local process loop |
| Alembic / Keycloak / OIDC / RBAC | No identity plane; env placeholders unread |
| `docker-compose` control plane | Operator starts Uvicorn + worker |
| OpenSearch, K3s, Kafka, Temporal | Not in this build |
| Streamlit, PyShark, second PDF renderer | Jinja + WeasyPrint only |
| Spicy IMAP analyzer | Escalation deferred; TShark corroborates |
| Organization policy packs | Only three built-in profiles |
| Imported OCSP/CRL/CT | Revocation stays `unknown` |
| RFC 3161 timestamps / signed reports | Manifest signature `unavailable` |
| Multi-node scale-out | Single-host only |
| Second ML model | Isolation Forest only after the frozen gate |
| LLM detector or compliance judge | Forbidden |
| Windows support | **Unsupported**, not merely deferred |
| Coverage threshold in CI | None configured |
| Package / container publish | Version `0.0.0`; see [release process](../development/release-process.md) |

`api/cli/commands/analyze.py` is an unused stub; that is leftover scaffolding,
not a deferred feature.

## Related pages

- [Known limitations](known-limitations.md)
- [Future index](../future/README.md)
- [AGENTS.md](../../AGENTS.md) §12

## Implementation anchors

- `src/securemail/bootstrap.py` (filesystem wiring only)
- `pyproject.toml` unused `api` extras
