---
status: proposed
audience: architect
authoritative_for: proposed case-level concentric attention metrics and GitHub-style unified evidence heatmap
last_verified: 2026-09-15
---

# Analyst snapshot: concentric attention metrics and unified evidence heatmap

## 1. Decision summary

Add one compact **Analyst snapshot** to the case workspace. It combines:

1. concentric attention metrics inspired by the supplied circular reference;
2. one consolidated evidence heatmap inspired by the supplied record-matrix
   reference and the compact contribution grids used by GitHub/LeetCode.

The references supply visual form only. Their labels such as “case risk”,
“clearance”, “health”, and “secure” are not adopted because SecureMail cannot
support those conclusions from passive capture evidence.

This is a frontend-only presentation phase over the existing
`securemail.report/v1` object. It does not change analyzers, normalization,
policy, findings, scoring, report assembly, API routes, HTML/PDF reports, or
the canonical schema.

Implementation must not start until this proposal is approved. It amends the
visual-only restriction in
[`dashboard-visual-redesign.md`](dashboard-visual-redesign.md) narrowly enough
to permit concentric metrics whose labels, numerators, denominators, null
states, and limitations are all explicit. It does not permit a system-health,
readiness, or percent-secure gauge.

## 2. Exact placement

The snapshot is rendered **inside the existing Assessment trust card as its
final ruled section**. It appears after provenance and after the current open
limitations or acknowledged-limit message, and before View focus and the case
tabs.

```text
Case identity
Assessment trust card
  trust-banner-main
  provenance
  full-provenance disclosure
  limitations or acknowledged-limit message
  Analyst snapshot                         <- new
View focus
Overview | Findings | Evidence | Analysis context
Active tab content
```

This placement makes the snapshot visible above every case tab while keeping
the trust decision and all limitations ahead of it. It must not be inserted
between `trust-banner-main` and the limitations panel, because that would ask
the analyst to read visual summaries before unresolved evidence.

The snapshot remains visible when the analyst changes tabs. Acknowledging
limitations collapses only the existing limitation content; it never changes
the snapshot data or colours.

## 3. Information architecture

Desktop uses one ruled row inside the trust card:

```text
ANALYST SNAPSHOT
┌───────────────────────────┬──────────────────────────────────────────┐
│ Concentric attention load │ Unified evidence contribution grid       │
│ exact values + legend     │ selected-record detail below the grid    │
└───────────────────────────┴──────────────────────────────────────────┘
```

- Rings receive approximately 4 of 12 columns.
- The heatmap receives approximately 8 of 12 columns.
- Below 960px the panels stack, rings first.
- The heatmap has an internal bounded scroller so it cannot push the case tabs
  arbitrarily far down the page.
- No panel uses glow, glass blur, ambient gradient, oversized rounding, or a
  marketing-dashboard treatment.

## 4. Concentric attention metrics

### 4.1 Centre value

The centre shows the canonical
**Highest endpoint priority (0–100)** from `posture.risk_score`.

- A numeric value is displayed as an integer, never as a percentage.
- A null value displays **Not proven** and uses the unresolved token.
- The accessible name repeats that this is endpoint priority and is not a
  system-health score.

### 4.2 Rings

All rings use an “attention share” direction: a longer arc means more review
is required. Every visible legend row includes the exact numerator,
denominator, and percentage derived from those values.

| Ring | Numerator | Denominator | Visible label | Token |
|---|---:|---:|---|---|
| Outer | `coverage.failed_count` | `coverage.applicable_count` | Failed policy checks | `--danger` |
| 2 | `coverage.unknown_count + coverage.not_observable_count` | `coverage.applicable_count` | Unresolved policy checks | split `--unknown` / `--not-observable` markers |
| 3 | mail sessions without published TLS establishment | all decoded mail sessions | TLS establishment not present in published evidence | `--warning` |
| Inner | handshakes whose `server_certificate_state` is `not_observable` | all TLS handshakes | Server certificate not observable | `--not-observable` |

“TLS establishment not present in published evidence” is intentionally not
called “cleartext” unless the canonical report explicitly supports that
conclusion. The existing same-UID session/handshake join is reused; the browser
does not decode traffic.

### 4.3 Null and empty behaviour

- A zero denominator displays **No applicable data** and an empty neutral
  rail. It does not display 0% in green.
- Unknown and not-observable values never contribute to pass counts.
- Ring values are presentation-only ratios. They are not persisted, hashed,
  exported, or used to reorder canonical findings.
- The component uses static inline SVG circles and the current CSS tokens. No
  new chart dependency is introduced and no arc animates on load.

## 5. GitHub/LeetCode-style unified evidence heatmap

### 5.1 Visual grammar

Use the interaction and density of a contribution calendar: small uniform
squares, tight consistent gutters, quiet group labels, a stepped legend, and
hover/focus inspection. GitHub documents its contribution calendar as a visual
overview in which an individual square can be selected for its detail; that
interaction is the reference, not the calendar's time semantics:
[`Viewing contributions on your profile`](https://docs.github.com/en/account-and-profile/how-tos/contribution-settings/viewing-contributions-on-your-profile).

SecureMail evidence records do not publish a meaningful daily timeline, so
the heatmap must not add month/day labels or imply chronological order. The
grid adopts the compact square language only.

### 5.2 Grid contents

The four separate evidence inventories are combined into one ruled component
with four labelled bands:

1. Flows
2. Mail sessions
3. TLS handshakes
4. Certificates

Each band uses the same square size, gutter, legend, selection behaviour, and
detail panel. Bands are separated by a hairline and a small label/count rather
than by four independent cards. This makes the result read as one heatmap.

**One square represents exactly one canonical evidence record.** It never
represents a packet, an invented health value, or a blended average.

Record identity is stable:

- flow, session, and handshake cells use `record_type + uid`;
- certificate cells use the canonical composite key
  `uid:role:chain_index:der_sha256`;
- published array order is retained inside each band and is explicitly called
  **report order**, not capture chronology;
- the selected detail joins the same UID to endpoint/protocol context when the
  canonical report supports it.

The presentation selector associates a record with canonical policy checks
whose `record_type` and `record_key` match exactly. A finding is associated
only through an exact `evidence_references[]` target. No fuzzy endpoint or
rule-code guess is used to colour a record.

### 5.3 Square colour and marker rules

The requested green–amber–red scale is discrete rather than interpolated. A
continuous blend would imply a score that the report does not publish.

| Square condition | Fill/rail | Required text or marker |
|---|---|---|
| Exact linked high negative finding | muted `--danger` | `HIGH` marker |
| Exact linked medium negative finding | muted `--warning` | `MEDIUM` marker |
| Exact linked low/informational negative finding | muted `--info` | exact severity marker |
| Exact linked failed check without a linked finding | muted `--danger` | `FAILED CHECK`; no invented severity |
| Exact linked pass-only checks with usable evidence | muted `--success` | `PASS` marker |
| Record or linked checks are unknown, incomplete, conflicting, or indeterminate only | `--unknown` pattern/marker | exact unresolved state |
| Record or linked checks are not observable only | `--not-observable` pattern/marker | `NOT OBSERVABLE` marker |
| Observed record with no applicable linked check | `--panel-subtle` with accent outline | `OBSERVED · NOT EVALUATED` |

For a record with mixed linked outcomes:

- the worst canonical deterministic result controls the square fill;
- the record's own evidence state remains visible through its outline or
  corner glyph;
- an unknown or not-observable linked check remains visible as a second corner
  marker;
- the selected-record details show every linked check and finding;
- any linked failure prevents the square from becoming green;
- unresolved evidence can never become amber or green.

The compact legend reads **Not evaluated · Pass · Attention · High
attention**, using neutral, green, amber, and red squares, followed by separate
lavender **Unresolved** and grey **Not observable** keys. This preserves the
requested green–yellow–red progression without pretending that missing
evidence sits somewhere on that result scale.

Colours reuse the implemented Evidence Ledger tokens:
`--success`, `--warning`, `--danger`, `--info`, `--unknown`,
`--not-observable`, and `--accent`. No inline semantic hex values are added.

### 5.4 Interaction

- The bands use one composite ARIA grid with roving focus; only the current
  square enters the tab order.
- Arrow keys move between squares; Home/End move within a band; Enter or Space
  selects a record.
- Selection uses the current accent outline and does not rely on colour.
- The accessible name includes record type, record key, evidence state, linked
  outcome, and the number of linked checks/findings.
- Selecting a square opens one persistent record inspector beneath the grid
  with:
  - record type and canonical key;
  - UID, endpoint, protocol, and record-specific summary facts when available;
  - exact record evidence state;
  - every exactly linked check with code, title, outcome, and evidence state;
  - every exactly linked finding with title, severity, and canonical score;
  - an action that opens the existing finding detail drawer.
- No information is available only through hover. Pointer hover may preview a
  square, but focus and selection provide the same content.
- The tiny desktop squares are a visualization, not the only action target.
  The record inspector supplies 40px-or-larger Previous, Next, and Open
  finding controls, and an accessible textual record list exposes the same
  values.
- Under `pointer: coarse`, squares enlarge and the grid scrolls horizontally
  rather than shrinking touch targets beyond usability.

### 5.5 Density and bounded rendering

- Desktop bands use 52 columns of 11–13px visual squares with 3px gutters,
  matching the dense cadence of a contribution calendar without copying its
  palette.
- Each evidence band initially renders up to 104 records: two desktop rows of
  52 squares. This prevents a large flow inventory from hiding sessions,
  handshakes, or certificates.
- A per-band **Show 104 more** action increases that band's limit without
  fetching another resource.
- The unified component has a fixed maximum height with internal scrolling on
  large reports. Every band states **Showing N of M records**.
- Empty bands show **No records published** and no fake green squares.
- Selecting another report identity resets the selected heatmap square and
  per-band limits, following the existing case-isolation contract.
- Long and hostile record/check/finding text continues through
  `render_forensic_text` and cannot become markup.

## 6. Existing information retained

The feature does not remove or replace:

- Assessment trust state, priority wording, coverage sentence, provenance,
  limitations, stage errors, or acknowledgement;
- View focus or case tabs;
- the endpoint-first risk tree;
- the 4 × 4 protocol/category coverage matrix and policy-check ledger;
- raw flow, session, handshake, and certificate views;
- the separate Deterministic Conclusions, Observed Facts, Advisory / ML, and
  Analyst Conclusions regions.

The heatmap is a compact record-navigation surface. The existing coverage
matrix remains the exact protocol/category accounting surface.

## 7. File-level implementation plan

| Path | Planned responsibility |
|---|---|
| `plans/proposals/analyst-snapshot-metrics-and-heatmap.md` | Approved contract before implementation |
| `frontend/src/core/selectors.ts` | Pure ring values, unified evidence cells, stable record keys, exact reference joins, and no report mutation |
| `frontend/src/core/selectors.test.ts` | Ratio, zero-denominator, grouping, precedence, stable-order, and immutability proofs |
| `frontend/src/components/attention_rings.tsx` | Static accessible SVG rings and exact textual ledger |
| `frontend/src/components/evidence_heatmap.tsx` | Contribution-grid bands, roving focus, bounded records, selection, and record inspector |
| `frontend/src/components/evidence_heatmap.test.tsx` | Square semantics, mixed states, keyboard interaction, hostile text, and per-band bounds |
| `frontend/src/components/trust_banner.tsx` | Compose the snapshot after limitations/acknowledgement and before the card closes |
| `frontend/src/components/case_view.tsx` | Pass the existing finding-selection callback into the trust snapshot; no route or tab change |
| `frontend/src/components/ui.tsx` | Reuse centralized tones; extend only if a marker cannot be expressed by the current primitives |
| `frontend/src/styles.css` | Ledger layout, SVG rails, heatmap cells, responsive stacking, forced-colour, print, and reduced-motion rules |
| `frontend/src/test/report_fixture.ts` | Component fixture coverage for complete, limited, null, mixed, and empty states |
| `tests/e2e/dashboard.spec.ts` | Placement, persistence above tabs, cell drill-down, responsive, keyboard, bounded, and case-isolation proofs |
| `docs/architecture/frontend-data-flow.md` | As-built selector/data-flow description after implementation passes |
| `docs/user-guide/dashboard-workflows.md` | Analyst interpretation and colour legend after implementation passes |

No generated canonical type is hand-edited. No backend file is expected to
change.

## 8. Implementation sequence

### Phase 0 — approve the contract

1. Review this proposal against the ring/gauge prohibitions in the implemented
   visual redesign.
2. Approve only the exact metrics, labels, placement, and colour rules above.
3. Freeze screenshots for complete, limited, none/Not proven, mixed coverage,
   large record count, and hostile text before component work.

### Phase 1 — selector contracts first

1. Add failing tests for all four ring numerators and denominators.
2. Add zero-denominator and null-priority tests.
3. Add one-cell-per-record, exact-reference joining, band ordering, and
   result-precedence tests.
4. Prove all canonical finding/check IDs are conserved and the report object is
   not mutated.
5. Implement only the pure selectors needed to satisfy those tests.

### Phase 2 — isolated components

1. Implement the static SVG ring component and its textual equivalent.
2. Implement the unified contribution grid and selected-record inspector.
3. Add keyboard, screen-reader, forced-colour, reduced-motion, and hostile-text
   component tests.
4. Keep colour/state mapping centralized through existing UI tokens.

### Phase 3 — trust-banner integration

1. Add the snapshot as the final ruled section inside `TrustBanner`.
2. Pass the existing finding selection handler from `CaseView` so a heatmap
   finding opens the established drawer.
3. Verify that limitations always precede the snapshot and that acknowledgement
   changes no metric.
4. Verify the snapshot remains above and visible with every case tab.

### Phase 4 — responsive and bounded behaviour

1. Validate the 4/8-column desktop composition.
2. Stack rings and heatmap below 960px without hiding labels or counts.
3. Prove the internal scroll and 104-record per-band increments against a
   large report.
4. Confirm the tabs remain reachable without horizontal page overflow.

### Phase 5 — full proof and documentation

Run:

```bash
npm --prefix frontend run lint
npm --prefix frontend run typecheck
npm --prefix frontend run test
npm --prefix frontend run build
make e2e
make test
make docs-check
```

Update live documentation only after all checks and visual QA pass.

## 9. Acceptance criteria

| ID | Proof |
|---|---|
| AS-01 | Snapshot is inside Assessment trust after limitations/acknowledgement and before View focus and tabs. |
| AS-02 | Changing Overview/Findings/Evidence/Analysis context leaves the same report-scoped snapshot visible above the tabs. |
| AS-03 | Centre value uses exact Highest endpoint priority wording; null is Not proven and never zero/green. |
| AS-04 | Every ring reconciles to its published numerator and denominator; zero denominators say No applicable data. |
| AS-05 | Ring direction is consistently “more attention”, and no ring claims health, readiness, clearance, or percent secure. |
| AS-06 | Heatmap has four bands in one component and renders exactly one square for every displayed flow, session, handshake, or certificate record. |
| AS-07 | Green appears only for pass-only usable checks; unknown and not observable remain lavender/grey and never become pass. |
| AS-08 | Mixed squares retain both the worst deterministic result and the record/unresolved markers; all exact linked checks and findings remain inspectable. |
| AS-09 | Heatmap selection exposes the canonical record key, evidence state, exact-reference checks/findings, and can open the existing finding drawer without re-scoring. |
| AS-10 | Each band is capped at 104 initial records, reports N of M, and expands only by explicit per-band action. |
| AS-11 | Desktop, tablet, mobile, keyboard-only, screen-reader, forced-colour, reduced-motion, and hostile-text tests pass. |
| AS-12 | Case switching resets snapshot interaction state and cannot leak another report’s endpoints or findings. |
| AS-13 | No API, analyzer, policy, scoring, canonical report, HTML report, or PDF report behaviour changes. |
| AS-14 | Existing trust, tabs, risk tree, coverage matrix, evidence views, downloads, and four authority-region tests remain green. |

## 10. Explicit non-goals

- No “overall security health” or readiness score.
- No average endpoint risk.
- No browser-side policy evaluation, scoring, deduplication, packet parsing, or
  TLS inference.
- No conversion of absent, incomplete, unknown, conflicting, indeterminate, or
  not-observable evidence into success.
- No replacement of the detailed coverage/check ledger or raw evidence views.
- No animated counters, rotating rings, pulsing cells, glow, neon palette, or
  decorative chart data.
- No server persistence for selected rings, heatmap cells, or expanded rows.
