---
status: implemented
audience: architect
authoritative_for: implemented dashboard visual language and visual-only implementation record
last_verified: 2026-09-15
---

# Dashboard visual redesign: Evidence Ledger

## 1. Decision summary

Redesign the SecureMail dashboard as an **evidence ledger**: a restrained,
dark, rule-based forensic workbench influenced by chain-of-custody forms,
protocol traces, and laboratory instruments.

This is a visual-system replacement, not a product or information-architecture
change. The implementation must preserve every current route, control,
interaction, state, label, disclosure, count, data field, and workflow. It must
continue to implement the analyst order in [`analyzer.md`](../../analyzer.md):

1. identify the capture and policy;
2. establish whether the assessment can be trusted;
3. prioritize endpoint findings;
4. locate the affected service and occurrences;
5. follow findings to facts and frames;
6. read remediation context;
7. review coverage and unresolved evidence;
8. keep advisory output and analyst conclusions separate.

The visual direction is derived from those evidence principles, not from the
current dashboard aesthetic. Current screens were inspected only to inventory
behavior and information that cannot be lost.

**Implementation record:** this post-Step-11 visual-only contract was approved
for implementation on 2026-09-15. The frontend implementation retains the
existing routes, report contract, and workflows.

## 2. Sources and boundaries

### Sources reviewed

- [`analyzer.md`](../../analyzer.md), especially the four information lanes,
  analyst journey, evidence-state rules, and visual-semantic prohibitions.
- The implemented analyst-first contract in
  [`analyst-dashboard-implementation.md`](analyst-dashboard-implementation.md).
- The route and shell contract in
  [`dashboard-navigation-simplification.md`](dashboard-navigation-simplification.md).
- Current rendered catalog, upload, case overview, findings, evidence, and
  detail-drawer views.
- `frontend/src/App.tsx`, `frontend/src/pages/`,
  `frontend/src/components/`, and `frontend/src/styles.css`.
- Existing Vitest and Playwright contracts.

### In scope

- A new visual language for every current dashboard surface.
- Typography, color, geometry, spacing, hierarchy, density, focus, motion, and
  responsive behavior.
- Restyling and visual composition of existing components.
- Visual accessibility and semantic-state consistency.
- Removing unused legacy CSS while retaining every live behavior.
- Visual-regression coverage and information-parity tests.

### Explicitly out of scope

- No route, navigation, tab, filter, grouping, sorting, pagination, selection,
  acknowledgement, upload, cancellation, polling, or download change.
- No new dashboard information and no removal, summarization, or hiding of
  current information.
- No canonical schema, selector semantics, policy, scoring, API, worker,
  analyzer, report, or persistence change.
- No packet parsing, policy evaluation, scoring, or inference in the browser.
- No light theme, theme switcher, persistent sidebar, command palette, global
  search, profile picker, trend view, or new write workflow.
- No marketing hero, decorative threat map, pseudo-terminal, fake activity
  feed, security-health gauge, or invented metric.
- No new iconography that implies a result not present in the report.

## 3. Current visual audit

The present dashboard is semantically much stronger than its appearance. It
already preserves the four authority regions, labels coverage gaps honestly,
keeps risk separate from health, and exposes evidence lineage. Those contracts
remain untouched.

The redesign addresses the following visual issues.

| Area | Current issue | Design response |
|---|---|---|
| Overall composition | Most content is placed in similar rounded cards, so trust, facts, conclusions, and secondary metadata look equally authoritative. | Replace the card grid with a ruled document hierarchy: page, section, record, annotation. |
| Visual character | Dark navy, cyan accents, glowing focus, pills, soft shadows, and rounded panels resemble a generic security/SaaS dashboard. | Use flat graphite surfaces, warm neutral type, square status flags, hairline rules, and deliberate mono data blocks. |
| Color | Cyan is used for brand, headings, focus, selected states, facts, and buttons; semantic meaning is diluted. | Reserve cyan for focus, links, selected navigation, and usable evidence. Use result colors only for labelled states. |
| Catalog | Four equal summary cards and a three-column case-card grid feel like a dashboard template. Static “Priority first” receives the same weight as urgent state. | Turn the summary into a compact docket header and cases into scan-friendly case rows while preserving every value and the open action. |
| Upload | A small dropzone sits in a large empty canvas and reads as a generic file uploader. | Present the same control as a centered intake sheet with chain-of-custody copy and a bounded scanner-slot drop target. |
| Trust gate | Priority, provenance, coverage, and limitations are visually compressed into one large card with many equally weighted boxes. | Make it a structured assessment docket with a dominant trust statement, narrow priority register, provenance ledger, and limitation annotation. |
| Section hierarchy | Repeated cyan uppercase eyebrows appear at nearly every level and lose their orienting value. | Use numbered section folios only at primary boundaries; use quiet labels and rules inside a section. |
| Risk tree | Endpoint, domain, and finding rows are all rounded containers. Hierarchy depends on nesting and whitespace more than alignment. | Use a tree ledger with a persistent endpoint rail, indented domain rules, and aligned finding columns. |
| Coverage | The matrix is useful but visually busy; the donut and colored tiles compete with the actual counts. | Retain the matrix and four-slice donut, but flatten both and make counts/labels primary. |
| Findings | Tree and table repeat the same visual language and create a long stack of similar panels. | Treat the tree as the action queue and the table as an evidence ledger with a distinct tabular texture. |
| Detail drawer | A `max-w-xl` drawer contains a two-column detail grid, compressing evidence and long forensic values. | Keep the drawer interaction but widen it to a desktop evidence sheet; use one column on narrow viewports. |
| Evidence | Sessions, handshakes, certificate chains, and flows share generic card styling even though they are different record types. | Give each record type a consistent ledger anatomy while retaining its specific timeline, chain, or list structure. |
| Small text | Many informational labels render at 10px or about 0.6rem, which is hard to scan in a dense forensic tool. | Set 12px as the minimum size for meaningful text and use spacing/weight instead of extreme miniaturization. |
| Mobile parity | `.risk-leaf-badges` is hidden below 560px, removing severity, evidence state, and score from the visible finding. | Never hide semantic data on mobile; wrap it onto a second line. |
| State consistency | A not-observable policy check can receive warning/amber styling while other not-observable views use unresolved grey. | Centralize state tokens. Not observable is always unresolved grey/lavender, never warning amber or pass green. |
| CSS ownership | `styles.css` retains large unused systems for command deck, analyst rings, bento cards, and evidence heatmaps. | Delete dead selectors during the visual reset and retain only styles referenced by live components. |

## 4. Design idea: an evidence ledger

The visual metaphor comes directly from SecureMail’s operating model.

- A capture is an evidentiary original with identity and provenance.
- Observations are records, not decoration.
- Findings are deterministic judgments attached to records.
- Coverage gaps are annotations on what could not be proved.
- Analyst conclusions are a separate human layer.

The interface therefore resembles a carefully indexed working paper rather
than a “cyber command center.” It should feel calm under incident pressure,
precise enough for review, and credible when printed in a screenshot.

### Visual attributes

- Flat, dark graphite canvas with no radial glow or ambient gradient.
- Warm off-white primary text to reduce blue-on-blue fatigue.
- Thin rules and alignment carry hierarchy; shadows do not.
- Small corner radii, mostly 2–6px, to distinguish records without making
  every item a floating card.
- Mono type only for identities, hashes, endpoints, codes, frames, protocol
  values, timestamps, and arithmetic.
- Large numbers are rare and attached to an explicit label and denominator.
- Status is expressed with text, a left-edge mark, and color together.
- Empty space is used to separate authority lanes, not to create a marketing
  layout.

### Explicit anti-patterns

The implementation must not introduce or retain:

- glassmorphism, backdrop blur, neon glow, radial spotlight backgrounds;
- gradient-filled metric cards or “bento” presentation;
- oversized rounded cards, pill clouds, or badges for ordinary metadata;
- shield/lock illustrations as evidence;
- red-to-green gauges, readiness rings, health percentages, or traffic-light
  summaries of the entire case;
- animated counters, pulsing results, celebratory pass states, or parallax;
- decorative topology graphs that imply relationships the report does not
  publish;
- placeholder charts whose shape carries no analytical meaning.

## 5. Foundation specification

### 5.1 Color tokens

The palette is deliberately desaturated. Semantic colors remain highly
legible on both canvas and panel backgrounds and are never the sole state cue.

| Token | Value | Use |
|---|---:|---|
| `--canvas` | `#0b0d0f` | Page background |
| `--panel` | `#111418` | Primary section surface |
| `--panel-subtle` | `#171b20` | Selected row, code block, inset record |
| `--panel-strong` | `#1d2228` | Active control or elevated drawer section |
| `--rule` | `#303740` | Structural border and divider |
| `--rule-strong` | `#46515c` | Selected/focused structure |
| `--text` | `#ece8de` | Primary text |
| `--text-soft` | `#c2c5c7` | Secondary text |
| `--text-muted` | `#929ba3` | Labels and helper copy |
| `--accent` | `#66b7c2` | Focus, link, active navigation, usable evidence |
| `--danger` | `#ff7b7b` | Act-now result/high negative severity |
| `--warning` | `#e0af63` | Important weakness/medium negative severity/limited assessment |
| `--unknown` | `#b6a5d8` | Unknown, incomplete, conflicting, indeterminate |
| `--not-observable` | `#a9b1b8` | Not observable and unavailable visibility |
| `--success` | `#79c69d` | An individual canonical policy pass only |
| `--info` | `#7fb7d5` | Low-severity/informational supporting state |

All meaningful text colors above exceed WCAG AA against `--canvas` and
`--panel`. Tinted backgrounds use the corresponding color at 8–14% opacity;
text continues to use the solid token. `--rule` is structural and is not used
for informational text.

No component may use an inline hex value for a canonical state. Semantic
mapping lives in one token table and one state-to-token function.

### 5.2 Semantic grammar

| Meaning | Text label | Marker | Color |
|---|---|---|---|
| Negative, high | `HIGH` plus canonical outcome | solid 3px left rule | danger |
| Negative, medium | `MEDIUM` plus canonical outcome | solid 3px left rule | warning |
| Negative, low | `LOW` plus canonical outcome | solid 3px left rule | info |
| Informational | `INFORMATIONAL` | 1px left rule | text-muted |
| Observed | `OBSERVED` | solid dot | accent |
| Verified | `VERIFIED` | double-ring dot | accent |
| Inferred | `INFERRED` | half-filled dot | info |
| Incomplete | `INCOMPLETE` | broken rule | unknown |
| Conflicting | `CONFLICTING` | crossed rule | unknown |
| Indeterminate / unknown | exact canonical label | open diamond | unknown |
| Not observable | `NOT OBSERVABLE` | open square | not-observable |
| Policy pass | `PASS` | check mark | success |
| Assessment complete | `COMPLETE ASSESSMENT` | neutral bracket | accent, never green |
| Assessment limited | `LIMITED ASSESSMENT` | warning bracket | warning |
| Assessment none | `NO ASSESSMENT` | unresolved bracket | unknown |

The exact text remains visible. Marker shapes must survive grayscale,
forced-colors mode, and common color-vision deficiencies.

### 5.3 Typography

Use one coherent technical family, locally bundled and pinned:

- **IBM Plex Sans Variable** for interface text and headings.
- **IBM Plex Mono** for evidence identifiers, protocol values, hashes,
  timestamps, rules, frame references, scores, and arithmetic.

The family was chosen for its documentary and engineering character, not for
a futuristic or terminal aesthetic. It must be bundled through pinned
Fontsource packages; no runtime font request is permitted.

| Role | Size / line height | Weight | Notes |
|---|---|---|---|
| Page title | 30 / 36px | 600 | Case ID may use mono at 28 / 34px |
| Section title | 21 / 28px | 600 | Primary workspace boundary |
| Record title | 16 / 22px | 600 | Endpoint, finding, handshake, chain |
| Body | 15 / 23px | 400 | Default explanatory copy |
| Dense body | 13 / 19px | 400–500 | Tables and ledgers |
| Label | 12 / 16px | 600 | Uppercase optional; letter spacing at most 0.06em |
| Evidence mono | 12–14 / 18–21px | 400–500 | `font-variant-ligatures: none` |
| Metric | 24–32 / 1 | 500 | `font-variant-numeric: tabular-nums` |

No meaningful text may render below 12px. Uppercase is reserved for canonical
states, compact labels, and section folios; ordinary prose remains sentence
case.

### 5.4 Spacing, grid, and density

- Base unit: 4px.
- Page gutters: 24px desktop, 20px tablet, 16px mobile.
- Maximum content width: 1520px.
- Primary section separation: 40px desktop, 32px mobile.
- Record row padding: 12px vertical, 14–16px horizontal.
- Panel padding: 20px desktop, 16px mobile.
- Desktop content grid: 12 columns with 20px gutters.
- Minimum interactive target: 40 × 40px; 44 × 44px on touch layouts.

Dense does not mean cramped. Repeated records may be compact, but a change of
authority lane always receives a larger break and a labelled top rule.

### 5.5 Shape and depth

- Page sections: 0–4px radius, one-pixel rule, no shadow.
- Controls: 4px radius.
- Status flags: 2px radius; never fully pill-shaped.
- Popovers/drawer only: subtle `0 18px 50px rgb(0 0 0 / 0.38)` shadow.
- Selected rows use a background tint plus a 2px accent rail.
- Hover changes background or rule color only; no translation or scale.

### 5.6 Icon rules

- Keep Lucide for controls already represented by icons: upload, download,
  copy, close, pagination, warning, and evidence visibility.
- Icons are 14–18px and always paired with a visible label unless the existing
  control is already named accessibly, such as Close or pagination arrows.
- Do not put icons in decorative circles.
- Do not assign a shield or lock icon to complete/pass; the text state is the
  authority.

## 6. Global layout

### 6.1 Application shell

Retain the exact shell behavior: logo link to `/cases` and one **Upload
capture** action. Do not add navigation.

- Header height: 56px.
- Opaque `--canvas` background, 1px bottom rule, no blur.
- Logo uses the existing asset at an optically legible height, without placing
  its black rectangle inside another dark rounded card.
- Upload action is a quiet bordered text button. On `/upload` it receives a
  2px bottom/left active marker instead of a filled cyan background.
- Main content begins 28px below the header on desktop and 20px on mobile.

### 6.2 Section folios

Primary case workspaces use a small mono folio at their top rule:

```text
01  ASSESSMENT TRUST
02  DETERMINISTIC CONCLUSIONS
03  COVERAGE REMAINDER
04  OBSERVED FACTS
```

The existing visible section names remain unchanged in headings and ARIA
labels. Folio numbers are presentational orientation, not new report data.
Within a section, do not repeat the same eyebrow before every child panel.

## 7. Screen specifications

### 7.1 Catalog `/cases`

**Intent:** a case docket, not a portfolio of metric cards.

The filter interaction, assessment-state select, sort order, case values, and
**Open case intelligence** action remain unchanged.

Desktop composition:

```text
┌ SECUREMAIL ────────────────────────────────────────── UPLOAD CAPTURE ┐
│                                                                     │
│ CASE DOCKET                                      [Filter] [State ▾] │
│ Cases                                                               │
│ Highest endpoint priority …                                         │
│                                                                     │
│ 6 PUBLISHED  |  1 IMMEDIATE ATTENTION  |  0 NOT PROVEN              │
│ Ordered: priority first                                             │
│ ─────────────────────────────────────────────────────────────────── │
│ 90 │ dashboard_critical       LIMITED │ H1 M2 L1 I3 │ U2 O1 │ OPEN │
│    │ dashboard_critical · generated timestamp · findings 7          │
│ ─────────────────────────────────────────────────────────────────── │
│ 73 │ capture-ad9f53ac         LIMITED │ H3 M3 L0 I0 │ U1 O0 │ OPEN │
└─────────────────────────────────────────────────────────────────────┘
```

Rules:

- Replace the four summary cards with one ruled summary line. Preserve the
  labels and values **Published cases**, **Immediate attention**, **Not
  proven**, and **Catalog order / Priority first**.
- Render each case as a full-width docket row on desktop. The row contains,
  without omission: case label, case ID, generated time, assessment state,
  highest endpoint priority or Not proven, finding count, all four severity
  counts, separate unknown and not-observable counts, advisory presence, and
  the open action.
- The priority is a left register, not a progress bar or circular gauge.
- Case label and case ID remain separate even when identical.
- Severity counts use compact labelled columns (`H`, `M`, `L`, `I`) with full
  accessible names.
- Advisory remains an explicit `ADVISORY` flag; it is not blended into
  deterministic counts.
- At tablet and mobile widths, the row becomes a two-part record sheet. No
  semantic field is hidden; status and counts wrap below identity.

### 7.2 Upload `/upload`

**Intent:** local evidence intake.

Preserve the accepted extensions, native file input, drag/drop, helper copy,
error behavior, Back to catalog link, job stage list, polling, cancellation,
failed/cancelled states, and completed navigation.

Desktop composition:

```text
                 01  CAPTURE INTAKE
             Upload a capture
     Analysis stays on this host. Analyzers have no network.

     ┌──────────────────────────────────────────────┐
     │  PCAP / PCAPNG                              │
     │  Drop capture here                          │
     │  or choose a file                           │
     │                                             │
     │  offline analysis · HTML and PDF reports    │
     └──────────────────────────────────────────────┘
             Back to catalog
```

Rules:

- Center an intake sheet of 640–720px within the page; do not leave the
  dropzone floating in the upper-left of an otherwise empty canvas.
- The dropzone is a flat panel with four small corner brackets and a single
  dashed inner rule. No icon bubble, glow, or gradient.
- Keep the current wording visible. “Drop PCAP / PCAPNG” remains the primary
  label.
- Errors appear as a danger annotation attached to the lower rule, with
  `role="alert"` unchanged.
- The in-progress view uses the same sheet and existing six stages in a
  vertical ledger. Completed stages show a labelled check, active stage uses
  an accent rule, and future stages remain neutral. Do not use pulsing status
  when reduced motion is requested.
- **Cancel analysis** remains visually distinct and in its current workflow;
  danger styling describes the action, not the run status.

### 7.3 Case identity header

Preserve Back to catalog, assessment badge, generated time, case ID, policy,
HTML download, and PDF download.

- Back to catalog is a small text link above the identity block.
- Case ID is the dominant mono title. Generated time and policy sit on one
  quiet metadata line.
- Assessment state appears adjacent to identity, not duplicated as a large
  decorative chip.
- HTML and PDF remain separate actions. PDF may be the stronger action, but
  neither receives a glow or gradient.
- Long hostile case identifiers wrap safely and never displace the report
  actions outside the viewport.

### 7.4 Assessment trust

**Intent:** the first and strongest case section.

Preserve every current badge/state, risk value, coverage sentence, capture
hash and copy action, policy, pack, analyzer, capture filename fallback, full
provenance disclosure, all limitation counts, notes, stage errors, and the
acknowledgement action/state.

Desktop composition:

```text
01  ASSESSMENT TRUST ─────────────────────────────────────────────────
LIMITED ASSESSMENT              HIGHEST ENDPOINT PRIORITY
Limitations can change          90 / 100
the conclusion                  not a system-health score

8 applicable  ·  3 passed  ·  2 failed  ·  2 unknown  ·  1 not observable
──────────────────────────────────────────────────────────────────────
CAPTURE SHA     POLICY       PACK          ANALYZER      CAPTURE FILE
aaaaaaaa…       ietf_current cccccccc…     bbbbbbbb…     not retained
▸ Full run provenance
──────────────────────────────────────────────────────────────────────
! TRUNCATED       ! FLOWS 1 / 1       ◇ CERTS 1       ◇ CHECKS 2 / 1
  limitation notes and stage errors
  [Acknowledge limits and continue]
```

Rules:

- Use a two-column opening row: assessment conclusion and priority register.
  Priority never appears without the exact label **Highest endpoint priority
  (0–100)** or the current explanatory text.
- Keep the coverage reconciliation as text, not a health bar.
- Provenance is a horizontally aligned ledger on wide screens and a two-column
  definition list on mobile.
- Limitations use an amber heading rule; unknown and not-observable values
  retain their own purple/grey semantics inside the section.
- The expanded/open behavior remains identical. Acknowledging limits reduces
  the section to its current acknowledged message but never removes the
  assessment, score, coverage, or provenance.
- Do not reduce opacity of the entire case panel before acknowledgement.
  Findings remain visually secondary through hierarchy and the open gate, not
  by making content harder to read.

### 7.5 View focus and case tabs

Preserve all focus choices and their current page-selection behavior:
Standard, Incident / IR, Mail owner, Protocol, PKI, and Historical. Preserve
Overview, Findings, Evidence, and Analysis context tabs, counts, sticky
behavior, arrow/Home/End keyboard navigation, and ARIA relationships.

- Put View focus in a slim toolbar immediately above the tabs.
- Render tabs as a ruled index, not a pill/segmented container.
- Visible labels stay exact. A quiet mono `01–04` may precede each label.
- Active tab uses a 2px accent underline and `--text`; inactive tabs use
  `--text-muted`.
- Counts remain visible in squared counters. No semantic count is hidden on
  mobile; the tab row may scroll horizontally as it does today.

### 7.6 Overview and endpoint-first risk tree

Preserve the trust-first intro, grouping choices, endpoint disclosures,
expanded default state, endpoint/service/protocol/session/cleartext values,
domains, finding title/code/occurrences/severity/basis state/score, unresolved
check count, empty state, and finding selection.

- Remove the duplicate visual treatment for “Analyst workflow” and
  “Deterministic conclusions.” Keep all copy, but place the workflow sentence
  as a margin note beneath the section folio.
- The grouping control remains four buttons with the same semantics. Style it
  as an underlined local index.
- Each endpoint is one ruled record. The summary uses aligned columns:
  endpoint, role/protocol, session/cleartext counts, highest score, disclosure
  marker.
- Domain headings are indented beneath the endpoint with a thin rule.
- Finding rows are grid-aligned: title/code/occurrences on the left;
  severity, evidence state, and score on the right.
- A 3px severity rail marks a negative finding. Evidence state retains its
  separate marker so result and confidence cannot be conflated.
- Unknown/not-observable check remainder is an unresolved annotation at the
  bottom of the endpoint record.
- On mobile, severity, evidence state, outcome, and score move below the title.
  They are never hidden.

### 7.7 Coverage matrix and overall disposition

Preserve all protocols, categories, P/F/U/O counts, cell selection/toggle,
policy-check filtering, clear filter, check ledger fields, Show 100 more,
four-slice donut, applicable count, and explanatory copy.

- The matrix remains a table because the exact protocol × category mapping is
  the content.
- Use flat cells with a 2px selected outline. P/F/U/O are textual mini-columns,
  not colored micro-pills.
- Zero-count cells remain visible and interactive.
- Keep a four-slice donut because it is part of the implemented contract, but
  use a thin ring with no shadow. The adjacent labelled count list is the
  primary reading.
- Passed is green; failed red; unknown purple; not observable grey. A
  not-observable policy-check badge must not use warning amber.
- On narrow screens, preserve horizontal table scrolling and keep the overall
  disposition directly below it. Do not collapse unknown and not-observable.

### 7.8 Findings ledger

Preserve search, Severity/Protocol/Evidence state filters, all options,
sortable columns, visible row data, finding selection, empty state, page
count, result count, and previous/next controls.

- Treat this as a ledger, visually distinct from the action tree: square table
  boundary, denser rows, tabular numbers, quiet zebra tint only when needed.
- Keep the current columns and order: Severity, Finding, Endpoint, Protocol,
  Evidence, Score.
- Sticky headers are permitted inside the existing scrolling table boundary;
  they must not cover the case tabs.
- The filter region is one labelled fieldset. Search may be wider; selects
  keep their visible labels.
- A row hover highlights the whole row, while only the existing finding title
  button opens detail.
- On mobile, preserve horizontal scrolling rather than dropping columns.

### 7.9 Finding evidence drawer

Preserve the sheet/drawer interaction, overlay close, Escape close, title,
severity, basis state, outcome, code, deterministic judgment, every detail
field, six-component score, arithmetic check, remediation context, standards,
occurrences, evidence-reference resolution states, direct frame, frame/record
context, resolved value, full lineage, and contributing occurrences.

- Desktop width: `min(920px, 76vw)`. Tablet: `min(760px, 92vw)`. Mobile:
  full viewport.
- Keep judgment and supporting facts as the two explicit columns from
  `analyzer.md`; switch to one column below 820px.
- The drawer header remains visible while scrolling and contains the current
  title and Close action.
- Lineage is a horizontal chain on desktop and vertical indexed list on mobile.
  Every node displays its evidence state in text.
- The six score components remain distinct and labelled. Use a flat segmented
  rule with the arithmetic below; no component becomes a circular chart.
- Resolved forensic values use an inset mono record with wrapping and visible
  control/bidi substitutions.
- Add correct focus containment and restore focus to the originating finding
  on close. This is an accessibility completion of the existing drawer, not a
  new workflow.

### 7.10 Evidence workspace

Preserve the selected-session behavior, 128-session cap, protocol and upgrade
labels, STARTTLS/STLS timeline, implicit TLS state, frames, downgrade caveat,
events, 64-handshake cap, handshake fields and messages, certificate absence
state, 64-chain cap, certificate fields, flow list/selection, 128-flow cap, and
all explanatory caveats.

#### Session selector and upgrade timeline

- Keep the two-column session selector/timeline layout on desktop.
- Session rows use a compact index plus UID, protocol, and upgrade state.
- The selected row uses an accent rail; no rounded cyan outline.
- The four main upgrade states remain a connected timeline. Fallback and
  violation branch downward exactly as today’s semantic model requires.
- Reached states use numbered nodes and explicit labels. Terminal evidence and
  frame chips remain visible.
- `downgrade_consistent` always shows the exact current caveat: **Pattern
  consistent with downgrade — not proof of an attacker.**

#### TLS handshakes

- Render each handshake as a structured record sheet: UID/visibility header;
  selected version, cipher, key exchange, and server-certificate state in an
  aligned definition grid; message sequence on a lower rule.
- The record does not inherit severity color from findings. These are facts.

#### Certificate chains

- Keep the vertical leaf-to-issuer order.
- Draw the chain as an indexed spine rather than nested cards.
- Path at capture and SAN identity remain independent adjacent columns.
- Time and revocation remain separate. `unknown` revocation is unresolved,
  never green.
- A not-observable certificate is a ruled grey placeholder record with the
  current TLS 1.3 explanation, not an empty success state.

#### Flow evidence

- Keep the current textual navigator; do not turn it into a synthesized graph.
- Flow rows preserve source, destination, protocol, TLS, bytes, quality, and
  selected state.
- The selected flow appears in a definition ledger rather than a graph canvas.
- Incomplete/conflicting quality uses unresolved styling and explicit text.

### 7.11 Analysis context

Preserve advisory items and count, advisory-present state, the exact
“Does not change deterministic findings” disclaimer, analyst conclusions and
empty read-only explanation, historical focus warning, and every provenance
field.

- Advisory / ML uses a dashed purple rule and a clear authority label.
- Analyst Conclusions uses a neutral ruled record and retains its read-only
  wording.
- The two areas remain side by side on wide screens and stacked on narrow
  screens; they must never share one container or combined count.
- Provenance is a full-width definition ledger below both regions.

## 8. Responsive contract

The redesign is responsive by reflowing, not deleting.

| Width | Behavior |
|---|---|
| `>= 1280px` | 12-column page grid; catalog docket rows; two-column evidence/detail compositions. |
| `960–1279px` | 8-column grid; trust/provenance wraps; drawer uses up to 92vw; evidence records may stack. |
| `640–959px` | Single primary column; tab and matrix horizontal scroll; case actions wrap; session selector stacks above timeline. |
| `< 640px` | 16px gutters; full-screen drawer; docket records stack; all status labels and counts remain visible; touch targets at least 44px. |

Release-blocking mobile rules:

- Never use `display: none` on severity, evidence state, outcome, score,
  unknown count, not-observable count, assessment state, or any provenance
  value currently shown on desktop.
- Tables and the coverage matrix may scroll horizontally. A separate card
  summary must not replace or omit their columns.
- Long hashes, endpoints, hostile strings, and rule codes wrap or scroll inside
  their own bounded region; they never widen the viewport.
- Sticky header and case tabs may coexist, but together must occupy no more
  than 112px of a 390 × 844 viewport.

## 9. Interaction and motion

No interaction is added or removed.

| Interaction | Visual response |
|---|---|
| Link/button hover | rule or text-color change, 120ms |
| Row selection | 2px accent rail + subtle panel tint, 140ms |
| Tab change | underline moves or cross-fades, 140–180ms |
| Details expand/collapse | content reveal only; browser-native disclosure remains usable |
| Drawer open/close | opacity + 12px horizontal translation, at most 180ms |
| Upload running | active-stage rule; optional non-essential opacity cycle |

Under `prefers-reduced-motion: reduce`, all translation, pulsing, and animated
underline movement is disabled. State changes remain immediate and visible.

Focus uses a 2px `--accent` outline with a 3px canvas offset. Danger controls
retain the same focus outline rather than replacing it with red. Forced-colors
mode uses system colors and visible borders; marker shape and label carry state.

## 10. Information and UX parity ledger

Implementation cannot be considered complete until every row below is proven.

| Surface | Information that must remain | Behavior that must remain |
|---|---|---|
| Shell | SecureMail logo, Upload capture | logo → `/cases`; action → `/upload`; sticky header |
| Catalog heading | Published catalog, Cases, endpoint-priority disclaimer | none |
| Catalog filters | search, all/complete/limited/none | same filtering and default sort |
| Catalog summary | published, immediate attention, not proven, priority-first order | summary updates from current case list |
| Case docket | label, ID, time, assessment, priority, findings, H/M/L/I, unknown, not observable, advisory | Open case intelligence |
| Case header | back, state, time, ID, policy, HTML, PDF | cache-clearing back; both downloads |
| Trust | state, priority/not proven, coverage sentence, all provenance, all limitations, notes/errors | copy hash; provenance disclosure; acknowledge |
| Focus | all six options | same tab-selection presets |
| Tabs | all four labels and counts | click and arrow/Home/End behavior; sticky |
| Risk tree | all modes, endpoints, roles, protocols, counts, domains, every finding field, unresolved count | grouping, expand/collapse, detail open |
| Coverage | 4 × 4 matrix, P/F/U/O, donut, applicable, explanatory copy, check ledger | cell toggle, clear, Show 100 more |
| Findings | all filters/options/columns/rows/pagination | search, filter, sort, page, detail open |
| Drawer | every judgment, score, remediation, reference, lineage, frame, value, occurrence | overlay/Escape/Close |
| Sessions | list, selection, protocol, hints, explicit/implicit TLS, events, frames | session selection and scrolling cap |
| Handshakes | UID, visibility, version, cipher, KX, cert state, messages/frames | bounded rendering |
| Certificates | full chain, path, identity, time, revocation, issuer/reference/signatures, absence state | bounded rendering |
| Flows | path list and every selected-flow fact | selection and bounded rendering |
| Context | advisory, disclaimer, analyst notes, historical warning, provenance | existing focus behavior |
| Upload | all intake copy, formats, errors, six stages, filename/status, cancel, terminal states | drag/drop, file choose, poll, cancel, navigate |
| Global states | loading and empty/error states | same query boundaries and case isolation |

## 11. Implementation plan

The work stays entirely inside the existing frontend unless a test-only helper
is needed. No backend or schema change is expected.

### Phase 0 — freeze behavior and content

1. Record current route/control/ARIA inventory from Playwright. Screenshots are
   reference for completeness only; they are not visual inspiration.
2. Add/extend tests for catalog fields, trust fields, mobile finding semantics,
   not-observable styling, drawer fields, evidence caps, upload stages, and
   context separation before restyling.
3. Capture representative report states:
   `dashboard_critical`, `dashboard_attention`, `dashboard_clear`, a Not
   proven/limited report, hostile text, certificate not observable, and empty
   findings.

### Phase 1 — replace foundations

1. Add pinned local IBM Plex Sans Variable and IBM Plex Mono packages.
2. Replace root color, type, spacing, focus, shape, and motion tokens in
   `frontend/src/styles.css`.
3. Refactor `Button`, `Card`, `Badge`, `Input`, `Sheet`, `LoadingState`, and
   `EmptyState` in `frontend/src/components/ui.tsx` to the ledger primitives.
4. Centralize result/evidence/visibility token mapping. Components must not
   invent their own outcome colors.
5. Delete unused command-deck, analyst-rings, bento, heatmap, and other orphaned
   selectors after an `rg` reference audit.

### Phase 2 — shell, catalog, and intake

1. Restyle the shell in `frontend/src/App.tsx` without changing its links or
   routes.
2. Recompose `catalog_page.tsx` into summary line + docket rows while retaining
   its filtering, sort, fields, test IDs, and open action.
3. Recompose `upload_page.tsx` into the intake sheet and stage ledger while
   retaining its state machine and API calls.
4. Prove desktop, tablet, and mobile content parity before proceeding.

### Phase 3 — case frame and trust gate

1. Restyle the identity header, report actions, focus toolbar, and case tabs in
   `case_view.tsx`.
2. Recompose `trust_banner.tsx` as the assessment docket. Preserve open and
   acknowledged states.
3. Remove whole-panel opacity reduction before acknowledgement; use hierarchy
   without reducing readability.
4. Prove complete, limited, none, scored, and Not proven states.

### Phase 4 — deterministic conclusions

1. Recompose `risk_tree.tsx` into aligned endpoint/domain/finding ledger rows.
2. Restyle `findings_table.tsx` and preserve every table capability.
3. Widen and restructure `finding_details.tsx`; complete focus containment and
   focus restoration.
4. Restyle `score_components.tsx` without changing arithmetic or labels.
5. Verify result, confidence, and visibility are simultaneously visible at
   tree, table, and drawer levels.

### Phase 5 — coverage and observed facts

1. Restyle `coverage_matrix.tsx`; centralize not-observable semantics.
2. Restyle `session_timeline.tsx`, `certificate_chain.tsx`, and
   `flow_topology.tsx` using record-specific ledger anatomy.
3. Recompose handshake and evidence sections in `case_view.tsx` without moving
   them between authority regions.
4. Prove bounded lists, hostile text, empty facts, implicit TLS, failed upgrade,
   certificate not observable, and conflicting flow states.

### Phase 6 — context, responsive polish, and cleanup

1. Restyle advisory, analyst conclusions, historical warning, and provenance.
2. Audit every breakpoint for information parity; remove the current mobile
   rule that hides finding badges.
3. Audit CSS for unused selectors and inline semantic colors.
4. Run lint, typecheck, unit tests, Playwright, production build, contrast
   checks, keyboard checks, and forced-colors/reduced-motion checks.
5. Update as-built user/development docs only after implementation passes.

## 12. File ownership

| File | Planned responsibility |
|---|---|
| `frontend/src/styles.css` | tokens, global layout, live component styles, responsive/forced-color/reduced-motion rules |
| `frontend/src/components/ui.tsx` | shared controls, state flags, ruled panels, drawer behavior |
| `frontend/src/App.tsx` | shell only |
| `frontend/src/pages/catalog_page.tsx` | summary docket and case records |
| `frontend/src/pages/upload_page.tsx` | intake and stage ledger |
| `frontend/src/pages/case_page.tsx` | no expected behavior change; loading/error framing only if needed |
| `frontend/src/components/case_view.tsx` | case identity, section folios, focus, tabs, workspace composition |
| `frontend/src/components/trust_banner.tsx` | assessment docket and limitations |
| `frontend/src/components/risk_tree.tsx` | endpoint/domain/finding ledger |
| `frontend/src/components/coverage_matrix.tsx` | matrix, donut, policy-check ledger |
| `frontend/src/components/findings_table.tsx` | filter/sort/pagination ledger |
| `frontend/src/components/finding_details.tsx` | evidence drawer and focus management |
| `frontend/src/components/score_components.tsx` | six-addend visual arithmetic |
| `frontend/src/components/session_timeline.tsx` | upgrade path and protocol events |
| `frontend/src/components/certificate_chain.tsx` | chain/path/identity/time/revocation record |
| `frontend/src/components/flow_topology.tsx` | textual flow navigator |
| `frontend/src/core/*` | no visual-design changes; selector/resolver semantics remain stable |
| `tests/e2e/dashboard.spec.ts` | route, parity, keyboard, responsive, and visual proofs |

Do not create a parallel design-system package or new top-level frontend
layout. Shared styles and primitives remain in the files that already own
them.

## 13. Verification contract

### Functional and information parity

- All existing Vitest and Playwright tests pass without weakening selectors or
  removing assertions.
- Add assertions for every row in §10 using representative fixtures.
- Compare a DOM-derived content inventory before and after the redesign; the
  redesign may add presentational folios but may not remove a visible canonical
  value or control.
- API/CLI canonical JSON equivalence remains unchanged.
- Catalog → case A → catalog → case B isolation remains proven.
- Upload, cancel, failure, completion, and download workflows remain proven.

### Visual regression set

Capture deterministic screenshots with animations disabled at 1440 × 1000,
1024 × 900, 768 × 900, and 390 × 844 for:

1. catalog with mixed case states;
2. empty/filtered catalog;
3. upload ready, invalid file error, running, failed, and cancelled;
4. limited trust gate open and acknowledged;
5. complete assessment with score 0;
6. limited/none assessment with Not proven priority;
7. overview risk tree and coverage;
8. all four finding groupings;
9. findings ledger with filters;
10. finding drawer with long evidence values;
11. coverage cell ledger open;
12. STARTTLS success, fallback, and violation;
13. certificate chain and certificate not observable;
14. conflicting flow selection;
15. Advisory / ML and Analyst Conclusions;
16. hostile strings.

Visual snapshots prove the approved specification, not similarity to the old
dashboard.

### Accessibility

- WCAG 2.2 AA contrast for text, controls, focus, and state markers.
- Every state survives grayscale and forced-colors mode through text + shape.
- Complete keyboard path through shell, filters, docket rows, tabs, groupings,
  disclosures, matrix, table, drawer, downloads, upload, and cancel.
- Visible focus never clips behind sticky UI.
- Drawer contains focus while open and restores it when closed.
- Semantic heading order remains valid; section ARIA labels and tab
  relationships are retained.
- Reduced-motion mode has no translation, pulse, or animated counter.
- At 200% zoom and 390px width, no canonical field disappears.

### Visual-quality gates

- No gradients, glow, glass blur, bento layouts, health gauges, or decorative
  security illustrations.
- No meaningful text below 12px.
- No unlabelled color-only state.
- Green appears only for individual passed policy checks.
- Complete assessment is neutral/accent, not green.
- Unknown, incomplete, conflicting, indeterminate, and not observable are never
  green; not observable is not amber.
- Risk is always labelled endpoint priority and null risk is always Not proven
  or an em dash.
- Result, confidence, and visibility remain distinguishable on the same object.
- Path, identity, time, and revocation remain independent certificate fields.
- Advisory and analyst conclusions remain visibly separate from deterministic
  conclusions.

### Performance and security

- No remote font, image, analytics, or asset request.
- No unsafe HTML or change to hostile-text rendering.
- No additional report fetch or browser-side recomputation.
- Bounded rendering limits remain in force.
- Production build adds no large visualization dependency for purely decorative
  work.

## 14. Definition of done

The redesign is complete only when:

1. the document is approved;
2. all phases in §11 are implemented within existing architecture boundaries;
3. the parity ledger in §10 has automated or explicitly reviewed proof;
4. the verification contract in §13 passes at all named states and viewports;
5. no old visual-system CSS remains referenced or orphaned;
6. as-built dashboard documentation is updated after the code lands;
7. a reviewer can answer the analyst’s questions in the order required by
   `analyzer.md` without interpreting a decorative chart or losing any current
   information.

## 15. Operating sentence

The dashboard should look like evidence being examined, not software trying to
look intelligent: identity first, limits in plain sight, conclusions attached
to facts, and every unknown left honestly unresolved.

## Related pages

- [Analyst evidence and risk tree](../../analyzer.md)
- [Analyst-first dashboard implementation](analyst-dashboard-implementation.md)
- [Dashboard navigation simplification](dashboard-navigation-simplification.md)
- [Dashboard workflows](../../docs/user-guide/dashboard-workflows.md)
- [Frontend data flow](../../docs/architecture/frontend-data-flow.md)
- [Frontend development](../../docs/development/frontend-development.md)
