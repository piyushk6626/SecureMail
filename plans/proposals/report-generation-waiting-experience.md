---
status: under-review
audience: product, design, frontend, accessibility
authoritative_for: proposed capture-analysis waiting experience and stage animation
last_verified: 2026-09-15
---

# Report generation waiting experience

## 1. Decision summary

Upgrade the `/upload` in-progress state from a passive six-row checklist into a
calm, stage-aware **analysis ledger**. The experience should make a long local
analysis feel deliberate and alive while remaining honest about what SecureMail
actually knows.

The proposed motion concept is a **ledger sweep**:

- the six real worker stages remain the source of truth;
- the active stage receives a short, looping tracer on its rule to communicate
  indeterminate work;
- the stage marker moves only when the API reports a new stage;
- completed stages settle into a neutral checked state;
- the header names the current operation in plain language and shows total
  elapsed time;
- no percentage, ETA, throughput, packet count, or completion forecast is
  invented.

This is a focused frontend refinement. It does not change packet analysis,
policy, scoring, report generation, the job API, worker concurrency, polling,
cancellation, or completed-run navigation.

## 2. Why the current screen feels unfinished

The current implementation in
[`upload_page.tsx`](../../frontend/src/pages/upload_page.tsx) and
[`styles.css`](../../frontend/src/styles.css) has the right six stages but does
not create a coherent waiting experience.

1. A queued job has no active visual state because the active class is applied
   only when `status === "running"`. The screenshot therefore presents six
   equally inactive rows while saying `queued`.
2. The shared `.run-stage > span` rule styles both the square marker and the
   text span. This makes the label layout fragile and contributes to the
   cramped, broken-looking stage names.
3. Every stage has nearly the same weight. There is no dominant answer to
   “what is happening now?”
4. The filename and raw status are shown, but the UI does not explain the
   current operation or reassure the analyst that processing remains local.
5. There is no elapsed-time context, so a normal long capture and an inert page
   feel identical.
6. The panel is visually disconnected from the rest of the Evidence Ledger:
   it uses the same rules and colors, but not the site’s stronger indexed-record
   hierarchy.
7. Cancellation remains available, but the UI does not visibly settle into a
   “cancellation requested” state after a running job accepts the request.

## 3. Truthful data boundary

The current `AnalysisJob` contract provides:

- `status`: queued, running, completed, failed, or cancelled;
- `stage`: intake, deterministic analysis, policy/scoring, ML advisory, report
  rendering, or publication;
- `created_at` and `updated_at`;
- `cancel_requested` and artifact availability.

It does **not** provide stage percentage, bytes processed, analyzer substage,
queue position, stage start time, ETA, or per-stage duration. The first
implementation must not add or simulate any of those values.

Total elapsed time may be derived from `created_at` and the client clock. It is
informational, is not announced every second to assistive technology, and stops
when the job becomes terminal. The existing one-second TanStack Query poll
interval remains unchanged.

## 4. Proposed experience

### 4.1 Page hierarchy

Retain the centered intake sheet, but widen the in-progress composition only as
needed for stable labels: approximately 720–800px on desktop and full available
width on mobile.

```text
CAPTURE PIPELINE                                      ELAPSED  01:42
Analyzing capture
securemail_ml_topology_1000flows.pcapng

┌──────────────────────────────────────────────────────────────┐
│ ACTIVE OPERATION                                      02 / 06│
│ Examining protocol and TLS evidence                         │
│ Zeek is analyzing the capture in a network-disabled worker. │
│ ────────────────  moving indeterminate tracer  ──────────── │
├──────────────────────────────────────────────────────────────┤
│ 01  ✓  Capture intake                              COMPLETE  │
│ 02  □  Deterministic analysis                    IN PROGRESS │
│ 03  □  Assemble report                                PENDING│
│ 04  □  Advisory evaluation                            PENDING│
│ 05  □  Report rendering                               PENDING│
│ 06  □  Publication                                    PENDING│
└──────────────────────────────────────────────────────────────┘

Analysis stays on this host. Long captures and PDF rendering can take time.
[ Cancel analysis ]
```

The active-operation block is the focal point. The full ledger remains visible
for orientation, but future stages are quiet and completed stages no longer
compete with the current work.

### 4.2 Stage language

Use a presentation metadata table in the frontend. It translates enum values
without changing their canonical meaning.

| API state | Visible active title | Supporting copy |
|---|---|---|
| queued + intake | Waiting for the local worker | Capture accepted, hashed, and queued for offline analysis. |
| deterministic_analysis | Examining protocol and TLS evidence | Zeek is analyzing the capture in a network-disabled worker. |
| policy_scoring | Assembling the deterministic report | Normalized evidence and scored findings are being wrapped in the canonical report. |
| ml_advisory | Evaluating advisory signals | Advisory analysis remains separate and cannot change deterministic findings. |
| report_rendering | Rendering report artifacts | The same canonical report is being rendered as JSON, HTML, and PDF. |
| publication | Publishing the local report | Report artifacts are being committed to the local catalog. |

The compact row labels should be `Capture intake`, `Deterministic analysis`,
`Assemble report`, `Advisory evaluation`, `Report rendering`, and
`Publication`. This avoids exposing the misleading historical implication that
the `policy_scoring` worker stage performs scoring; scoring is already part of
deterministic analysis.

### 4.3 Motion language: ledger sweep

Motion must feel like the same product as the case tabs and evidence drawer:
short, precise, low-amplitude, and rule-based.

- **Continuous active cue:** a 28–40px accent segment traverses the active
  horizontal rule over roughly 1.6 seconds, pauses briefly, then repeats. It is
  clearly indeterminate and never fills the full track like a percentage bar.
- **Stage transition:** when polling reports a new stage, the active rail and
  marker move to the next real row over 180–220ms using the existing site ease
  curve. The old row changes to `COMPLETE`; the new title cross-fades.
- **Completed marker:** use a neutral/accent check and text, not green. The
  Evidence Ledger reserves green for individual canonical policy passes.
- **Queued state:** keep the tracer in the active-operation block and label the
  first row `QUEUED`; do not mark intake as actively analyzing.
- **Cancellation:** after `cancel_requested` becomes true, stop the decorative
  tracer, disable the button, and show `Cancellation requested…`. The stage
  remains truthful until the API reports `cancelled`.
- **No remount on polling:** the animation is keyed by `stage`, not
  `updated_at` or the whole job object, so the one-second response refresh does
  not restart it.
- **No celebratory finish:** completion continues to navigate directly to the
  report. A brief stage transition may occur naturally, but there is no success
  burst, confetti, scale bounce, or artificial delay.

Use the already-installed `motion` package for stage/title transitions and CSS
for the small continuous tracer. No animation or UI dependency is added.

### 4.4 Visual integration

- Reuse `--canvas`, `--panel`, `--panel-subtle`, `--rule`, `--rule-strong`,
  `--text`, `--text-muted`, and `--accent`.
- Retain IBM Plex Sans for copy and IBM Plex Mono for stage index, status,
  filename, and elapsed time.
- Use square markers, thin rules, a 2px active rail, and at most a 4px radius.
- Do not add gradients, glow, glass blur, a large spinner, an orbital graphic,
  skeleton report data, or a pseudo-terminal.
- Do not use red or green to describe ordinary pipeline progress. Red remains
  attached to the destructive cancel action and failure state.
- Give long or hostile filenames a bounded, wrapping forensic-text region so
  they cannot distort the ledger.

### 4.5 Responsive behavior

- At 640px and above, keep stage number, marker, label, and state aligned in
  stable columns.
- Below 640px, keep the marker and label together and move the state below or
  to the right without hiding it.
- Keep the cancel target at least 44px high on touch layouts.
- At 200% zoom and 390px width, no stage label, current state, elapsed label,
  filename, or cancel state disappears.

## 5. Accessibility contract

- Render the stages as an ordered list; mark the real current item with
  `aria-current="step"`.
- Put the current phase title and job status in one `role="status"` region with
  `aria-live="polite"`. Polling must not cause repeated announcements when the
  phase has not changed.
- Keep the per-second elapsed timer out of the live region.
- The current, completed, queued, and pending states must be expressed with
  visible text and marker shape, not color alone.
- Under `prefers-reduced-motion: reduce`, remove the looping tracer and all
  translation. Stage and title changes become immediate or use a brief opacity
  change no longer than 100ms.
- Under forced colors, preserve the current-stage rail, marker outline, status
  text, and button boundaries with system colors.
- Animation must not flash, spin continuously, zoom, or exceed three changes
  per second.

## 6. Implementation plan

### Phase 1 — stabilize structure and state semantics

1. In `frontend/src/pages/upload_page.tsx`, replace the string-only `STAGES`
   array with typed stage presentation metadata.
2. Split marker and copy into explicit elements/classes so marker sizing can
   never constrain label width.
3. Derive four presentation states: queued, active, complete, and pending.
4. Add an active-operation summary with phase index, truthful title, supporting
   copy, filename, and total elapsed time.
5. Preserve all existing API calls, query keys, poll cadence, error/cancel
   branches, and completed navigation.

### Phase 2 — add the motion system

1. Add the indeterminate ledger tracer to the active-operation block.
2. Use `AnimatePresence`, `motion`, and `useReducedMotion` for real stage-title
   and active-marker transitions.
3. Ensure background polling does not remount or restart the stage transition.
4. Add the accepted cancellation-request state and stop decorative motion once
   cancellation is pending.

### Phase 3 — integrate with the Evidence Ledger

1. Replace `.run-ledger` and `.run-stage` with narrowly scoped progress styles
   in `frontend/src/styles.css`.
2. Add desktop, tablet, mobile, reduced-motion, and forced-colors rules.
3. Verify typography, color, border, radius, spacing, and motion timing against
   the implemented dashboard visual contract.
4. Remove only progress selectors proven unused after the replacement; do not
   disturb unrelated user changes in the shared stylesheet.

### Phase 4 — verify behavior and polish

1. Add Vitest coverage for queued, each running stage, cancel-requested, failed,
   cancelled, and completed transitions.
2. Assert the visible stage language, `aria-current`, live-region behavior,
   elapsed-time format, and absence of a percentage or ETA.
3. Extend Playwright coverage to hold a job in queued and running states before
   completion, then verify cancel and report navigation remain unchanged.
4. Capture deterministic screenshots with animations disabled at 1440×1000,
   768×900, and 390×844 for queued, deterministic analysis, report rendering,
   cancellation requested, failed, and cancelled states.
5. Run frontend typecheck, lint, Vitest, build, and the upload Playwright path.
6. Update `docs/architecture/frontend-data-flow.md` and
   `docs/user-guide/dashboard-workflows.md` after implementation to document
   the truthful stage presentation and accessibility behavior.

## 7. Primary file map

| File | Planned responsibility |
|---|---|
| `frontend/src/pages/upload_page.tsx` | stage metadata, active-operation summary, elapsed timer, cancellation presentation, semantic ordered list |
| `frontend/src/styles.css` | ledger layout, tracer, state markers, responsive/reduced-motion/forced-colors behavior |
| `frontend/src/App.test.tsx` | job-state and accessibility regression tests |
| `tests/e2e/dashboard.spec.ts` | queued/running/cancel/completion browser workflow |
| `docs/architecture/frontend-data-flow.md` | as-built polling and presentation behavior |
| `docs/user-guide/dashboard-workflows.md` | analyst-facing waiting and cancellation guidance |

No backend, schema, analyzer, policy, scoring, report renderer, or persistence
file is part of the initial implementation.

## 8. Acceptance criteria

The proposal is complete when all of the following are true:

- A queued job has an unmistakable, truthful `Waiting for the local worker`
  state instead of six inactive rows.
- The active operation is the strongest element on the page and all six stages
  remain visible.
- Stage labels do not collapse, clip, or wrap into narrow vertical columns at
  desktop, mobile, 200% zoom, or with the longest allowed filename.
- The only continuous animation is a restrained, visibly indeterminate tracer
  associated with the current operation.
- The marker advances only after the API reports a stage change.
- Elapsed time is visible, uses `created_at`, and is never presented as an ETA.
- There is no fake percentage, synthetic packet activity, fake artifact status,
  or invented worker substage.
- Reduced-motion and forced-colors modes remain fully understandable.
- Cancellation, failure, cancellation-requested, completion, navigation,
  polling, and download behavior remain functionally unchanged.
- Existing upload and case-isolation tests pass, and the new queued/running
  waiting-state tests pass.
- The result reads as part of the Evidence Ledger rather than a generic loading
  screen.

## 9. Explicitly deferred

Queue position, real stage start/end timestamps, per-stage duration history,
analyzer subprocess progress, and ETA would require a separate backend and job
contract proposal. They are not prerequisites for this visual upgrade and must
not be approximated in the browser.
