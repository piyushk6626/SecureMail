# CLI and development

## Command

Entry point: `securemail = "securemail.api.cli.main:main"`
([`pyproject.toml`](../pyproject.toml)). `main()` loads the Typer app from
[`bootstrap.create_cli()`](../src/securemail/bootstrap.py).

```bash
uv run securemail analyze <capture.pcap|capture.pcapng> --out <path.json>
```

- `--out` is required.
- Optional `--analysis-time` (RFC 3339 UTC) freezes `valid_at_analysis_time`.
- Optional `--expiry-warning-days` (default 30) sets the expiry warning window.
- Optional `--expected-hostname` sets the RFC 9525 reference identity
  (`reference_identity_source=configured`). Default: observed SNI.
- Capture must exist, be a file, and be readable (Typer checks).
- Parent directories of `--out` are created.
- JSON: `indent=2`, `sort_keys=True`, `ensure_ascii=False`, trailing newline.
- Extracted certificate DER is written under `<out-parent>/certificates/<sha256>.der`.
- Success: exit 0. `AnalysisError`, `InvalidCaptureError`, `FileNotFoundError`,
  `OSError`: message on stderr, exit 1.

No other subcommands are registered. `api/cli/commands/analyze.py` is an unused
Step 0 stub; the live command is `register_analyze` in
[`api/cli/main.py`](../src/securemail/api/cli/main.py).

```bash
uv run securemail analyze tests/fixtures/empty/capture.pcapng --out out/empty.json
```

## Make targets

From [`Makefile`](../Makefile):

| Target | Action |
|---|---|
| `make doctor` | `tools/doctor.py` workstation checks |
| `make sync` | `uv sync --all-extras` |
| `make lint` | ruff check + ruff format --check, mypy, import-linter |
| `make test` | pytest on `tests/unit`, `tests/support`, and `tests/` except `tests/fixtures/generators` |
| `make analyzer-lock` | regenerate `tools/analyzer-bundle.lock` |
| `make zeek-image` | build `securemail/zeek:step0` with bundle/base digest build-args |
| `make tshark-image` | build `securemail/tshark:step0` |

On Darwin the Makefile exports `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib`
so the uv interpreter can load Homebrew Pango (needed later for WeasyPrint;
doctor already checks Pango). Do not `brew install weasyprint`.

## Doctor

[`tools/doctor.py`](../tools/doctor.py) prints every check, then exits 1 if any
failed (hint is for the first failure). Checks:

| Line | Requirement |
|---|---|
| uv ≥ 0.11 | `uv` on PATH |
| python 3.13.x via uv | `uv python find 3.13` |
| git-lfs installed | `git lfs version` |
| docker daemon reachable | `docker info` |
| zeek/zeek@sha256:73e80e9c… matches lock | lock digest + image or manifest |
| pango visible via pkg-config | ≥ 1.58 |
| openssl reports OpenSSL (not LibreSSL) | macOS: `/opt/homebrew/bin/openssl` only |
| node/nvm | skipped until Step 11 |

`SECUREMAIL_CI=1` (set in GitHub Actions) still runs the checks; it prints that
Docker Desktop-specific notes are skipped.

## Toolchain pins

- CPython **3.13** via uv — not 3.14, not Homebrew/system Python
- Zeek **8.0.10** digest in the lockfile — not 8.2 / 9.x unless lock + fixtures
  are deliberately refreshed
- OpenSSL cross-check (Step 6 differential tests): Homebrew
  `/opt/homebrew/bin/openssl` on macOS, never `/usr/bin/openssl` (LibreSSL)
- git-lfs for `*.pcap`, `*.pcapng`, `*.der`, `*.p12`, `*.pfx`; JSON is ordinary
  git text
- Frontend Node 22 is pinned in `frontend/.nvmrc` but unused

## Lint

`make lint` runs:

- `ruff check` / `ruff format --check` on `src`, `tests`, `tools`
- `mypy` strict on package `securemail`
- `lint-imports` with the three contracts in [architecture.md](architecture.md)

## Tests

`make test` does **not** execute generator scripts as tests
(`--ignore=tests/fixtures/generators`).

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
| `tests/unit/test_reconstruction_quality.py` | Pure classifier |
| `tests/unit/test_normalize_flows.py` | Log joining |
| `tests/unit/test_normalize_sessions.py` | Identity, merge, corroboration gate |
| `tests/unit/test_{smtp,imap,pop3}_upgrade.py` | State machines |
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
| `tests/unit/test_truncated_stream_never_complete.py` | Named never-complete case |
| `tests/unit/test_fixture_diff.py` | Harness diff helper |

The harness compares **every** field, including `run_identity` digests and Zeek
UIDs. Changing `zeek/`, the lockfile, `_CONFIGURATION`, or
`trust-store-snapshot.pem` requires regenerating affected `expected.json` files.

## CI

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml):

1. Checkout with LFS, uv Python 3.13, Pango/Cairo apt packages, `uv sync --extra dev`
2. `SECUREMAIL_CI=1 make doctor`
3. `make lint`
4. Pull pinned Zeek image, `make zeek-image`, `make tshark-image`
5. `make test`

A second job resolves the pinned Zeek and Debian Trixie digests via
`docker manifest inspect`.

## Bootstrap (new workstation)

```bash
git lfs install
uv sync --extra dev
docker pull zeek/zeek@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3
make tshark-image
make zeek-image
make doctor
make lint
make test
```

Lab capture generation on macOS uses a tcpdump/dumpcap **sidecar** on the
Docker bridge (`NET_RAW` / `NET_ADMIN`). Host `tcpdump` on `en0` will not see
container-to-container traffic. Details:
[`tests/fixtures/generators/README.md`](../tests/fixtures/generators/README.md).

## Not in this build

No `securemail score` / `report` / `evaluate-ml`. No `make` target for a
frontend dev server. No docker-compose control plane.
