---
status: current
audience: contributor
authoritative_for: test inventory and how to run it
last_verified: 2026-09-06
---

# Testing

```bash
make test
```

That runs pytest on `tests/unit`, `tests/support`, and `tests/` except
`tests/fixtures/generators`, then Vitest (`npm --prefix frontend run test`).
There is **no** coverage threshold in CI or pytest config.

Playwright is a separate target: `make e2e`. It sets
`SECUREMAIL_ANALYSIS_STUB=1` in `frontend/playwright.config.ts` so e2e does
not start Docker analyzers.

The harness compares **every** field, including `run_identity` digests and
Zeek UIDs. Changing `zeek/`, the lockfile, `_CONFIGURATION` in
`run_analysis.py`, or `trust-store-snapshot.pem` requires regenerating
affected `expected.json` files — see [golden updates](golden-updates.md).

## Pytest inventory

Migrated from the former `docs/cli-and-development.md` test table, plus
post-Step-11 modules.

| Path | Role |
|---|---|
| `tests/support/fixture_harness.py` | Invoke real CLI; `diff_json` full equality vs `expected.json` |
| `tests/test_empty_fixture.py` | Step 0 + byte-identical rerun |
| `tests/test_tcp_fixtures.py` | Step 1 cases + never-complete snaplen assertion |
| `tests/test_protocol_fixtures.py` | Step 2 identity assertions |
| `tests/test_starttls_fixtures.py` | Step 3 upgrade / implicit TLS assertions |
| `tests/test_tls_fixtures.py` | Step 4 version/cipher/key-exchange assertions |
| `tests/test_certificate_fixtures.py` | Step 5 certificate fact assertions |
| `tests/test_certificate_chain_fixtures.py` | Step 6 path/identity fixtures, no-inet guard |
| `tests/test_policy_fixtures.py` | Step 7 YAML findings on named PCAPs |
| `tests/test_scoring_fixtures.py` | Real CLI score fixtures plus error exits |
| `tests/test_report_fixtures.py` | Real CLI report proof plus error exits |
| `tests/test_evaluate_ml.py` | Cohort CLI gates |
| `tests/test_report_api.py` | FastAPI/CLI byte identity and case isolation |
| `tests/test_analysis_api.py` | Capture upload HTTP: magic, quota, status, cancel, downloads |
| `tests/test_capture_acceptance.py` | Real `empty` PCAP through sandboxed analysis → HTML/PDF |
| `tests/unit/test_analysis_workflow.py` | Worker stages: failure, cancel, publication |
| `tests/unit/test_capture_intake.py` | Streaming intake, filename sanitization, duplicate reuse |
| `tests/unit/test_writable_catalog.py` | Catalog publish, replace, 256-entry cap |
| `tests/unit/test_job_store.py` | Quarantine, claim, artifacts |
| `tests/unit/test_reconstruction_quality.py` | Pure classifier |
| `tests/unit/test_normalize_flows.py` | Log joining |
| `tests/unit/test_normalize_sessions.py` | Identity, merge, corroboration gate |
| `tests/unit/test_smtp_upgrade.py` | SMTP STARTTLS machine |
| `tests/unit/test_imap_upgrade.py` | IMAP STARTTLS machine |
| `tests/unit/test_pop3_upgrade.py` | POP3 STLS machine |
| `tests/unit/test_implicit_tls.py` | ALPN vs port |
| `tests/unit/test_starttls_hypothesis.py` | Property tests |
| `tests/unit/test_run_analysis.py` | Intake / orchestration with fakes |
| `tests/unit/test_normalize_handshakes.py` | Version precedence, history, HRR frames |
| `tests/unit/test_key_exchange.py` | TLS 1.2 grammar vs TLS 1.3 key_share/PSK |
| `tests/unit/test_iana_tls_parameters.py` | Snapshot bounds and lookups |
| `tests/unit/test_chain_validation.py` | Path validation at explicit times |
| `tests/unit/test_identity.py` | RFC 9525 SAN matching; no CN fallback |
| `tests/unit/test_trust_store.py` | Pinned snapshot bounds and digest |
| `tests/unit/test_openssl_crosscheck.py` | OpenSSL vs cryptography differential |
| `tests/unit/test_analyzer_argv.py` | No shell metacharacters |
| `tests/unit/test_bundle_lock.py` | Lock hashing |
| `tests/unit/test_capinfos_parse.py` | capinfos text |
| `tests/unit/test_evidence_state.py` | Enum completeness |
| `tests/unit/test_scoring.py` | Exact v1 score tables and caps |
| `tests/unit/test_dedup.py` | Endpoint collapse, mixed packs, shuffle stability |
| `tests/unit/test_posture.py` | Coverage reconciliation and ordering |
| `tests/unit/test_report_schema.py` | Report JSON Schema, mutation, golden validation |
| `tests/unit/test_canonical_json.py` | RFC 8785 vectors and pinned golden hash |
| `tests/unit/test_html_renderer.py` | Autoescape, hostile-input, finding codes |
| `tests/unit/test_pdf_renderer.py` | PDF text, page range, font/WeasyPrint pins |
| `tests/unit/test_report_queries.py` | Bounded report parsing and case lookup |
| `tests/unit/test_report_repository.py` | Filesystem catalog bounds and traversal |
| `tests/unit/test_assemble_report.py` | Evidence → canonical envelope |
| `tests/unit/test_truncated_stream_never_complete.py` | Named never-complete case |
| `tests/unit/test_fixture_diff.py` | Harness diff helper |
| `tests/unit/test_rule_engine.py` | Tri-state evaluator |
| `tests/unit/test_policy_packs.py` | Pack load bounds |
| `tests/unit/test_forward_secrecy.py` | FS table |
| `tests/unit/test_key_strength.py` | Effective-strength bits |
| `tests/unit/test_parse_certificate.py` | DER bounds |
| `tests/unit/test_normalize_certificates.py` | Leaf validation attachment |
| `tests/unit/test_certificate_store.py` | Content-addressed DER store |
| `tests/unit/test_ml_baselines.py` | Median/MAD, rarity, Page-Hinkley |
| `tests/unit/test_ml_isolation_forest.py` | Challenger adapter |
| `tests/unit/test_ml_evaluation.py` | Gate arithmetic |
| `tests/unit/test_advisory_pipeline.py` | Findings stay byte-identical |
| `tests/unit/test_advisory_history.py` | Local window history |

## Frontend tests

| Path | Role |
|---|---|
| `frontend/src/App.test.tsx` | Case isolation, four regions |
| `frontend/src/core/evidence_resolver.test.ts` | Relative/qualified paths, composite certificates, derived fields, dangling records |
| `frontend/src/core/selectors.test.ts` | Zero-filled coverage, domain/group projections, immutable view-model selectors |
| `frontend/src/components/coverage_matrix.test.tsx` | 16-cell matrix and canonical check-ledger filtering |
| `frontend/src/core/forensic_text.test.ts` | Control/bidi visibility |
| `tests/e2e/dashboard.spec.ts` | Playwright catalog, preview, upload stub |

## Related pages

- [Fixture contract](fixture-contract.md)
- [CI](ci.md)
- [Make targets](make-targets.md)

## Implementation anchors

- `Makefile` `test` / `e2e`
- `pyproject.toml` `[tool.pytest.ini_options]`
- `frontend/playwright.config.ts`

## Test evidence

- CI `lint-test` runs `make test`
- CI `dashboard-e2e` runs `make e2e`
