---
status: current
audience: architect
authoritative_for: classification of plan documents
last_verified: 2026-09-11
---

# Plans

`plans/` holds requirements, completed implementation contracts, and historical
design. It is **not** the live description of the running system. That lives in
[`docs/README.md`](../docs/README.md).

Approved post-Step-11 UI work lives under [`proposals/`](proposals/README.md).
Ideas that appear in the 2026-09-02 technical design (PostgreSQL,
Celery/RabbitMQ, OIDC, Kubernetes) remain deferred unless a file appears under
`proposals/` and is explicitly approved.

## Classification

| Folder | Status | Role |
|---|---|---|
| [`requirements/OBJECTIVE.md`](requirements/OBJECTIVE.md) | completed | Original product requirements |
| [`completed/build-plan-steps-0-11.md`](completed/build-plan-steps-0-11.md) | completed | Steps 0–11 contracts and proof commands |
| [`completed/capture-dashboard.md`](completed/capture-dashboard.md) | completed | Capture-upload dashboard contract |
| [`history/technical-design-2026-09-02.md`](history/technical-design-2026-09-02.md) | historical | Broad design; includes unimplemented control-plane options |
| [`history/project-scaffold-2026-09-03.md`](history/project-scaffold-2026-09-03.md) | historical | Pre-development layout and toolchain baseline |
| [`history/exports/`](history/exports/README.md) | historical | Frozen HTML copies; Markdown is canonical |
| [`proposals/dashboard-navigation-simplification.md`](proposals/dashboard-navigation-simplification.md) | current | Dashboard routes, dark-only shell, no sidebar |
| [`proposals/analyst-dashboard-implementation.md`](proposals/analyst-dashboard-implementation.md) | current | Analyst-first dashboard implementation contract based on `analyzer.md` |

## Authority

1. Live behavior: `src/`, `zeek/`, tests, then `docs/`.
2. Engineering constraints: [`AGENTS.md`](../AGENTS.md).
3. Completed contracts: this directory’s `completed/` folder.
4. Historical design is a source of *why*, not a source of *what to build next*.

When a completed contract and the code disagree, document the code in
[`docs/status/known-limitations.md`](../docs/status/known-limitations.md).

## Related pages

- [Documentation hub](../docs/README.md)
- [Current capabilities](../docs/status/current-capabilities.md)
- [Deferred scope](../docs/status/deferred-scope.md)
- [Future reference architecture](../docs/future/README.md)
