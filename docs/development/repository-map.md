---
status: current
audience: contributor
authoritative_for: repository layout as filled by Steps 0–11
last_verified: 2026-09-06
---

# Repository map

Authoritative tree for *this* repository: the layout below (filled by
Steps 0–11). The historical scaffold is
[`plans/history/project-scaffold-2026-09-03.md`](../../plans/history/project-scaffold-2026-09-03.md).
Later work **fills named files**; it does not invent a new top-level layout.
Reconciled deviations are in [`AGENTS.md`](../../AGENTS.md) §6.

```text
src/securemail/
  api/            Typer CLI + thin FastAPI routers
  application/    use cases (orchestrate only)
  domain/         pure models and rules
  ports/          typing.Protocol only
  adapters/       Zeek/TShark, PKI, reports, ML, filesystem stores
  bootstrap.py    ONLY module that imports a port AND its adapter
  worker.py       python -m securemail.worker
zeek/             hashed as one bundle
docker/zeek/      Zeek image
docker/tshark/    TShark image
frontend/         React + Vite (Node 22)
tests/fixtures/   PCAP cases, synthetic_findings, reports, dashboard
tests/unit/       pure-function and adapter tests
tests/support/    harness + synthetic ML cohort
tests/e2e/        Playwright dashboard.spec.ts
tools/            doctor, lock refresh, fixture expected refresh
docs/             as-built documentation (this tree)
plans/            contracts and provenance — not live behavior
```

## Where new code goes

| Need | Put it in |
|---|---|
| Zeek/TShark invocation | `adapters/analyzers/`, behind `ports/analyzers.py` |
| Canonical evidence | `domain/evidence/` |
| STARTTLS / TLS / PKI / rule packs | `domain/policies/` |
| Scoring / dedup / posture | `domain/findings/` |
| Use-case orchestration | `application/` |
| IANA, trust store, cert bytes, reports, ML | named `adapters/` |
| Wiring | `bootstrap.py` only |
| Step proof | `tests/fixtures/<case_id>/` plus unit tests next to the pure function |

Avoid a generic `utils` package.

## Live application modules

| Path | Role |
|---|---|
| `application/run_analysis.py` | Intake, hash, analyzers, normalize, policy, score |
| `application/assemble_report.py` | Wrap evidence in `securemail.report/v1` |
| `application/capture_intake.py` | Bounded PCAP upload |
| `application/analysis_workflow.py` | Worker stages |
| `application/render_report.py` | One dump → JCS / HTML / PDF |
| `application/report_queries.py` | Catalog lookup |
| `application/advisory_pipeline.py` | ML after findings; never mutates `Finding` |

`api/cli/commands/analyze.py` is an unused Step 0 stub. Live `analyze` is
`register_analyze` in `api/cli/main.py`.

## Related pages

- [Coding and import boundaries](coding-and-import-boundaries.md)
- [Architecture index](../architecture/README.md)
- [AGENTS.md](../../AGENTS.md)

## Implementation anchors

- `src/securemail/bootstrap.py`
- `pyproject.toml` `[tool.importlinter]`
