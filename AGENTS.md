# SecureMail — Agent Instructions

This file is the standing brief for every agent working in this repository. Follow it
before writing code, tests, fixtures, Dockerfiles, or documentation.

The three plan documents remain the detailed contracts. Do not invent architecture,
layout, or step order that contradicts them. If they disagree, this file states the
reconciled rule (taken from `plans/PROJECT_SCAFFOLD.md` Section 8).

| Question | Source of truth |
|---|---|
| *What* to build and *why* | `plans/TECHNICAL_DESIGN.md` |
| *In what order*, and *what test proves it* | `plans/build_plan.md` |
| *Where files live*, toolchain, import boundaries | `plans/PROJECT_SCAFFOLD.md` |
| Product requirements / deliverable list | `plans/OBJECTIVE.MD` |
| How agents must work in this repo | **this file** |

Read the owning plan section for the step you are implementing. Do not re-derive
Zeek vs Python responsibility, the fixture contract, or the layer map from first
principles.

---

## 1. What this product is

SecureMail is an **AI-assisted, deterministic-first, offline/on-premise** passive
network-forensics tool. It assesses the cryptographic posture of **SMTP, IMAP, and
POP3** traffic from **PCAP / PCAPNG** files.

Pipeline in order:

1. Intake and hash the capture.
2. Zeek (primary) + bounded TShark (corroboration) in a network-disabled sandbox.
3. Normalize analyzer output into canonical evidence models.
4. Apply versioned, effective-dated policy packs → `Finding` records.
5. Score, dedup, and publish coverage denominators.
6. Freeze a canonical JSON report; render HTML/PDF from that object.
7. Optional advisory ML, strictly after and separate from deterministic findings.
8. Dashboard (Step 11) over the same JSON contract the CLI already produces.

Python **orchestrates**. It does **not** re-implement packet parsing, TCP reassembly,
or TLS record decoding. Zeek is the primary processing engine.

---

## 2. Current project state

This repository has completed **Steps 0–4** of `build_plan.md`: package layout,
sandboxed Zeek/TShark runners, the v0 evidence schema, TCP reconstruction
quality, payload-driven SMTP/IMAP/POP3 identification, STARTTLS/STLS plus
implicit-TLS assessment, and TLS version / cipher / key-exchange evidence. The
live CLI command is `securemail analyze`. The next step to implement is
**Step 5** (certificate extraction and per-certificate analysis).

The tree in `PROJECT_SCAFFOLD.md` Section 3 is the layout Step 0 created;
later steps **fill named files**, they do not invent new top-level layout.
As-built documentation of the live pipeline is under `docs/` (see
`docs/README.md`); `plans/` remains the contract for unimplemented steps.

Do not:

- Scaffold `frontend/` beyond the Step 0 placeholder (`.gitkeep` + `README.md` +
  `.nvmrc`) until Step 11.
- Add Postgres, RabbitMQ, Celery, Alembic, Keycloak, or `docker-compose` for the
  control plane before the CLI path has proven the logic (build_plan Ground rule 3).
- Start Step N before Step N−1 exit criteria are met.
- Put real policy, ML, or report code into a step that does not own it.

---

## 3. Non-negotiable ground rules

These apply to every change.

1. **Zeek first, Python second.** Packet ingest, TCP reassembly, protocol ID, TLS
   handshake decoding, and X.509 extraction happen in Zeek. Python normalizes,
   applies policy, scores, and renders.
2. **CLI-only until Step 11.** Every step is proven with `securemail <command>`
   against committed fixtures. FastAPI routers wrap the same `application/` use
   cases the CLI already calls — no new business logic in routes.
3. **Deterministic before AI.** Steps 0–9 must be fully deterministic, versioned,
   and fixture-tested before Step 10. ML consumes deterministic output; it never
   replaces, gates, suppresses, downgrades, or rewrites a `Finding`.
4. **Evidence states are mandatory.** Every applicable field in `expected.json`
   uses exactly these states (defined once in `domain/evidence/run.py`):
   `observed`, `verified`, `inferred`, `incomplete`, `conflicting`,
   `not_observable`, `indeterminate`. A test that treats `not_observable` /
   `incomplete` / `indeterminate` as “no weakness detected” / “secure” is a **bug
   in the test**.
5. **Test-first for Steps 0–9.** Author `tests/fixtures/<case_id>/` (capture +
   `expected.json` + `provenance.json`) and review it **before** the Zeek script
   or Python that should satisfy it. Step 9 is schema-first + golden snapshot.
   Step 10 is evaluation-harness-first. Step 11 is API/UI-contract-first.
6. **One step, one runnable proof.** A step is not done until its CLI command
   against named fixtures passes, including the exit criteria in `build_plan.md`.
7. **Missing evidence is not a pass.** TLS 1.3 certificates after `ServerHello`
   are `not_observable` unless authorized secrets/telemetry exist. Do not
   fabricate them. ECH can hide SNI. Capture loss makes reconstruction
   `incomplete` or `conflicting`, never silently `complete`.
8. **No network during analysis.** Analyzers run `--network=none`. No AIA, OCSP,
   CRL, CT, DNS, MTA-STS, model, or telemetry fetch from an analysis worker.
   Enrichment is imported, hashed, timestamped, and retained as evidence.
9. **Never build analyzer commands through a shell.** Fixed argv arrays only.
   Allowlisted TShark fields only. No unbounded full-tree dissection.
10. **Do not repair evidential originals.** Hash at intake (`capture_sha256`
    before any analyzer runs), analyze working copies, preserve competing TCP
    reconstructions when the bytes do not support one deterministic stream.

---

## 4. How to implement a build-plan step

Work one step at a time. For the current step:

1. Read that step in `plans/build_plan.md` (deliverables, fixtures, test contract,
   implementation, CLI command, exit criteria).
2. Confirm the target files in `plans/PROJECT_SCAFFOLD.md` Sections 3–4. Put code
   only in the file that owns the responsibility. Do not create parallel modules.
3. Author or extend fixtures **first** (except Steps 10–11, which use the
   approaches named in those steps).
4. Implement Zeek-side work (if any), then Python-side work, matching the step’s
   Implementation section.
5. Wire new behavior through existing ports/use cases. Do not have the CLI or a
   future router import adapters.
6. Prove with the step’s CLI command and `make test` / the fixture harness.
7. Stop at the step’s exit criteria. Do not pull in the next step’s files.

If Zeek built-in events are too coarse (Step 2 decision gate), escalate per
protocol to a small Spicy analyzer **or** a bounded TShark second pass, and
record the choice in `docs/decisions/step2-imap-pop3-depth.md`. Never skip that
write-up.

### Step map (do not skip or merge)

| Step | Owns | Proof command (see build_plan for exact fixtures) |
|---|---|---|
| 0 | Package layout, sandbox runners, `EvidenceState`, fixture harness, analyzer lockfile | `securemail analyze tests/fixtures/empty/capture.pcapng` |
| 1 | TCP reconstruction quality | `… tcp_snaplen_truncation …` |
| 2 | SMTP/IMAP/POP3 ID (`port_hint` ≠ `payload_evidence`) | `… pop3_nonstandard_port …` |
| 3 | STARTTLS/STLS state machines + implicit TLS correlation | `… imap_starttls_capability_stripped …` |
| 4 | TLS version / cipher / key exchange | `… tls13_hello_retry_request …` |
| 5 | Certificate facts (not policy findings) | `… cert_expired_rsa1024 …` |
| 6 | Chain + identity (independent fields; offline trust store) | `… cert_chain_san_mismatch …` |
| 7 | Versioned rule packs + forward secrecy | `… tls13_psk_only_resumption --policy-profile ietf_current` |
| 8 | Scoring, dedup, coverage denominators | `securemail score …` |
| 9 | Canonical JSON → HTML/PDF | `securemail report …` |
| 10 | Advisory ML after baseline gate | `securemail evaluate-ml …` |
| 11 | FastAPI + React over the same JSON | Playwright + CLI/API diff |

Facts vs findings: Step 5 records “RSA-1024”. Step 7 decides whether that is a
finding. Do not collapse those layers.

---

## 5. Architecture and import rules

Clean architecture with a single composition root. Enforced by `import-linter`
in `pyproject.toml` and CI — not by review convention.

```text
api/ (Typer CLI now; FastAPI routers at Step 11)
  -> application/          # use cases; orchestrate only
    -> domain/             # pure models and rules
    -> ports/              # typing.Protocol only
adapters/ implement ports and may return domain models
bootstrap.py is the ONLY module that imports a port AND its adapter
```

| Layer | May import | Must not |
|---|---|---|
| `domain/` | stdlib, Pydantic, other `domain/` | `adapters/`, `ports/`, `application/`, `api/`, I/O, Docker, subprocess |
| `application/` | `domain/`, `ports/` | concrete `adapters/`, `docker`, SQLAlchemy, Celery |
| `adapters/` | `ports/`, `domain/` | `application/`, `api/` |
| `api/` | `application/` (via bootstrap wiring) | business rules, Zeek/TShark, PKI crypto |
| `ports/` | stdlib, typing, domain types as signatures | `docker`, `subprocess`, SQLAlchemy, sklearn |

`domain/` evidence models are constructed by normalizers in `application/`, not
by the models parsing raw Zeek/TShark output themselves.

Avoid a generic `utils` package. Put code in the domain or adapter that owns it.

### Canonical records (do not invent parallel ones)

`Case`, `Capture`, `AnalysisRun`, `Flow`, `EmailSession`, `TlsHandshake`,
`CertificateEvidence`, `Finding`, `AnomalyResult`, `ReportManifest`, `AuditEvent`.

`AnomalyResult` is never merged into `Finding`.

Idempotency key for a run:

`(capture_sha256, analyzer_bundle_digest, normalization_schema_version,
policy_pack_version, trust_store_digest, configuration_digest)`

---

## 6. Layout — where new code goes

Authoritative tree: `plans/PROJECT_SCAFFOLD.md` Section 3. Reconciled deviations:

- Zeek scripts live in top-level `zeek/` (hashed as one bundle), not a loose
  `scripts/securemail-email.zeek`.
- Images: `docker/zeek/Dockerfile` and `docker/tshark/Dockerfile`.
- `tshark_image_digest` in `tools/analyzer-bundle.lock` is the SHA-256 of
  `docker/tshark/Dockerfile`, not the built-image digest originally named in
  scaffold §4.7. That is more reproducible than a local docker build id; it is
  still a deviation.
- Fixtures: `tests/fixtures/<case_id>/`, not `tests/golden_pcaps/`.
- Until Step 11, the only real `api/` adapter is `api/cli/` (Typer). `api/main.py`
  and `api/routers/` exist from Step 0 as empty placeholders.

| Need | Put it in |
|---|---|
| Zeek/TShark invocation | `adapters/analyzers/`, behind `ports/analyzers.py` |
| Canonical evidence | `domain/evidence/` |
| STARTTLS / TLS / PKI / rule packs | `domain/policies/` (pure functions + YAML data) |
| Scoring / dedup / posture | `domain/findings/` |
| Use-case orchestration | `application/run_analysis.py` (or `advisory_pipeline.py` at Step 10) |
| IANA TLS registry, trust store, cert bytes, reports, ML | `adapters/` as named in the scaffold |
| Wiring | `bootstrap.py` only |
| Tests that prove a step | `tests/fixtures/<case_id>/` + unit tests next to the pure function |

`tools/analyzer-bundle.lock` is generated by `tools/refresh_analyzer_lock.py`.
Never hand-edit it (same discipline as `uv.lock`).

---

## 7. Toolchain (do not substitute)

Pinned by `PROJECT_SCAFFOLD.md`. Re-verify claims (digests, wheels) rather than
silently changing versions.

| Tool | Rule |
|---|---|
| Python | **CPython 3.13** via `uv`. Not 3.14, not system Python, not Homebrew Python. |
| Deps | `uv` + committed `uv.lock`. `uv sync --extra dev` for Steps 0–8. |
| Analyzers | Docker images **pinned by digest**, `--network=none`, `--read-only`, non-root `65532`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--pids-limit=256`, `--memory=2g`, `--cpus=2`. |
| Zeek | `zeek/zeek:8.0.10` LTS, digest in the scaffold / lockfile — not 8.2 or 9.x unless the lockfile + every fixture are deliberately refreshed. |
| TShark | Separate image from `debian:trixie-slim` digest; lock records Dockerfile SHA-256, not the built-image digest; GPL; never statically linked. |
| OpenSSL cross-check | Homebrew `/opt/homebrew/bin/openssl` on macOS. **Never** `/usr/bin/openssl` (LibreSSL). Production validation uses Python `cryptography`; OpenSSL is test-only. |
| Fixtures | git-lfs for `*.pcap`, `*.pcapng`, `*.der`, `*.p12`, `*.pfx`. JSON stays normal git text. |
| PDF | WeasyPrint + Homebrew `pango`; `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib` on macOS. Bundled fonts under `adapters/reports/fonts/`, never system fonts. Do not `brew install weasyprint`. |
| Frontend | Node **22 LTS** via `frontend/.nvmrc`. Not the machine’s global Node 25. |
| Lab captures on macOS | tcpdump sidecar on the Docker bridge (`NET_RAW`/`NET_ADMIN`). Host `tcpdump` on `en0` will not see container-to-container traffic. |

Dependency extras: `core` (default), `reports` (Step 9), `ml` (Step 10), `api`
(Step 11), `dev` (always for contributors). Do not add FastAPI/sklearn to the
default CLI extra early.

Commands: `make doctor`, `make sync`, `make lint` (ruff, mypy, import-linter),
`make test`, `make analyzer-lock`.

---

## 8. Fixtures and evidence

```text
tests/fixtures/<case_id>/
  capture.pcapng    # LFS, never edited after creation
  expected.json     # authored BEFORE code; reviewable git text
  provenance.json   # source, generator path+args, tool versions, sha256, created_at
```

`<case_id>` is `<protocol_or_area>_<condition>` matching names already used in
`build_plan.md` (`tcp_snaplen_truncation`, `imap_starttls_capability_stripped`,
`tls13_hello_retry_request`, `cert_expired_rsa1024`, `cert_chain_san_mismatch`,
`tls13_psk_only_resumption`, …). Guessable from the step, not invented.

Fixture sources (pick per case as the step specifies):

- **Lab** — real handshakes/certs (Postfix/Dovecot/Cyrus + openssl in Docker).
- **Scapy** — malformations and capture-quality cases a real stack will not emit.
- **Public corpus** — regression only; never the sole proof of a rule.

Generator scripts live in `tests/fixtures/generators/` and are part of the
evidence chain. Do not delete or rewrite in place once a fixture points at them;
change means a new script or a new fixture.

Treat every capture, banner, certificate string, and report field as **hostile**.
Bound parser size/nesting. Escape all decoded content in HTML/PDF/UI. Jinja2
autoescape stays on — never disable per-template.

---

## 9. Domain rules agents get wrong if they improvise

- Protocol ID is payload-driven. Ports are `port_hint`, not proof. Ambiguous
  banners are `indeterminate`, not a guess.
- Implicit TLS (465/993/995) must correlate with decoded protocol, not port alone.
- STARTTLS: explicit per-protocol state machines (`advertised`, `requested`,
  `accepted`, `tls_established`, `plaintext_fallback`, `violation`).
  `downgrade_consistent` is its own field — not “STARTTLS missing” and not proof
  of an attacker.
- TLS version: `supported_versions` wins over the legacy record-layer version.
- TLS 1.3 key exchange comes from `key_share` / groups / PSK modes — **never**
  from cipher-suite name. Cipher names/codes come from the checked-in IANA
  snapshot, not hardcoded Python literals.
- Certificate signature algorithm ≠ handshake `CertificateVerify` algorithm.
  Keep them separate. Expiry: `valid_at_capture_time` and
  `valid_at_analysis_time` are independent.
- Path validity and `identity_match` are independent. SAN matching is RFC 9525;
  **no CN fallback**. Revocation without imported OCSP/CRL is `unknown`.
- Forward secrecy: TLS 1.2 ECDHE → present; static RSA/DH/ECDH → absent; TLS 1.3
  (EC)DHE → present; TLS 1.3 PSK-only / missing handshake → `indeterminate`.
  Never claim ephemeral-key reuse or ticket rotation from one PCAP.
- Policy is YAML data (`ietf_current`, `nist_federal`, `historical_at_capture`,
  later `organization_*`). SMTP relay (25) ≠ submission (465/587) ≠ IMAP/POP3
  access. “Not FIPS-approved” ≠ “cryptographically weak”.
- Scoring is a versioned pure function. Dedup collapses session findings to
  endpoint findings **without dropping** contributing session references.
  `unknown_count` / `not_observable_count` must appear in posture; never fold
  them into “checks passed”.
- JSON is authoritative. HTML and PDF render the **same in-memory object**.
  Canonicalize with RFC 8785 before hashing.

---

## 10. ML / dashboard (when those steps are open)

- Baseline (median/MAD, categorical rarity) is committed and scored first.
  `isolation_forest.py` must not exist until a committed test shows it beats the
  baseline by a stated margin.
- `--advisory` is off by default. Reports keep “Deterministic Findings” and
  “Advisory / ML” as separate sections.
- Every anomaly needs a concrete, evidence-linked reason string, not “anomaly
  detected”.
- Do not train on case evidence without separate authorization. Do not use raw
  IPs/names/serials as supervised features. No autoencoders/sequence models in
  early releases. No LLM as a detector, compliance judge, or command executor.
- Dashboard: contract tests must show API JSON ≡ CLI JSON (modulo run
  timestamp). UI must label four regions: observed facts, deterministic
  conclusions, ML advisories, analyst notes. No-case-selected must not leak
  another case.

---

## 11. Coding conventions

- Python: `def` for pure functions, `async def` for I/O. Type hints on all
  signatures. Pydantic v2 models over raw dicts. RORO for use cases.
- Guard clauses and early returns; happy path last. `HTTPException` only for
  expected API errors (Step 11).
- Functional domain code; no classes-for-everything. Adapters may be small
  concrete classes that implement `Protocol`s.
- Directories and files: `lowercase_with_underscores`.
- Do not log packet payloads, credentials, private/session keys, or unnecessary
  PII.
- Air-gapped target: pin by digest, commit lockfiles, keep trust stores / IANA
  data / rule packs in-repo as versioned files.

---

## 12. What not to do

- Do not break encryption or recover plaintext without authorized key material.
- Do not treat this as a Wireshark replacement, an active scanner, or a tool
  that mutates mail-server config.
- Do not let an ML model or LLM make final compliance, attribution, legal, or
  IR decisions.
- Do not silently continue if an analyzer image digest does not match
  `analyzer-bundle.lock`.
- Do not add OpenSearch, K3s, Kafka, Temporal, Streamlit, PyShark, or a second
  PDF renderer because they appear in the design’s alternatives list. Those are
  deferred unless a later phase explicitly starts them.

When in doubt, open the plan section for the step, put the code in the scaffold
path that already names that job, write the fixture first, and keep evidence
states honest.
