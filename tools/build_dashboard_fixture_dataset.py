"""Build a standalone dashboard catalog from capture fixture expectations.

The tool deliberately reads the reviewed ``expected.json`` for every capture
fixture instead of re-running the containerized analyzers.  That makes the
dataset fast, deterministic, and exactly representative of the test contract.
It has no imports from ``securemail`` and needs only the Python standard
library.

Examples:

    python tools/build_dashboard_fixture_dataset.py
    python tools/build_dashboard_fixture_dataset.py --out out/demo-fixtures
    python tools/build_dashboard_fixture_dataset.py --config dataset.json

``--print-default-config`` emits the complete JSON configuration shape. CLI
options override values supplied by ``--config``. Capture-byte hash validation
is opt-in because the reviewed fixture contract is authoritative for this
display-only dataset and historic fixture captures can be regenerated.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

CATALOG_SCHEMA_VERSION = "securemail.report-catalog/v1"
DATASET_SCHEMA_VERSION = "securemail.dashboard-fixture-dataset/v1"
REPORT_SCHEMA_VERSION = "securemail.report/v1"
DEFAULT_GENERATED_AT = "2026-09-06T00:00:00Z"
CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")
EVIDENCE_KEYS = frozenset(
    {
        "schema_version",
        "run_identity",
        "capture_preflight",
        "flows",
        "sessions",
        "handshakes",
        "certificates",
        "findings",
        "policy_checks",
        "posture",
    }
)
DEFAULT_RENDERER = {
    "html_renderer": "securemail.html/v1",
    "pdf_renderer": "weasyprint",
    "pdf_renderer_version": "69.0",
    "template_name": "report.html.j2",
    "template_sha256": "9af49e7a478bad9d874034675f2268ff1d16dbc4d206b2cb20fecdeb1ff53b9d",
    "fonts": [
        {
            "family": "Noto Sans",
            "filename": "NotoSans-Regular.ttf",
            "sha256": "1f0826e3f6488a3c14fe54d0ebf860bfad1bc1cc952fd4755ff519f145c9c17e",
            "style": "normal",
            "weight": 400,
        },
        {
            "family": "Noto Sans",
            "filename": "NotoSans-Bold.ttf",
            "sha256": "23f831d62059cc0d0cb4e71dbc9aadd1717d23c457028d81001c925e8a78cd5c",
            "style": "normal",
            "weight": 700,
        },
        {
            "family": "Noto Sans Mono",
            "filename": "NotoSansMono-Regular.ttf",
            "sha256": "213857674181ec82bf4f825a1ddb4b2a30136ca07a30e954c229b816108fc23d",
            "style": "normal",
            "weight": 400,
        },
    ],
}


class DatasetError(Exception):
    """Raised when fixture evidence cannot safely become a dashboard report."""


@dataclass(frozen=True)
class DatasetConfig:
    fixture_root: Path
    output_root: Path
    dashboard_report_root: Path
    case_id_prefix: str = "fixture-"
    generated_at: str = DEFAULT_GENERATED_AT
    include: tuple[str, ...] = ("*",)
    exclude: tuple[str, ...] = ()
    max_cases: int | None = None
    validate_capture_sha256: bool = False
    include_analyst_notes: bool = True
    include_dashboard_cases: bool = True
    replace_existing: bool = False
    renderer: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_RENDERER))
    dependency_versions: dict[str, str] = field(
        default_factory=lambda: {"dataset_generator": "stdlib/v1"}
    )


@dataclass(frozen=True)
class DatasetResult:
    output_root: Path
    case_ids: tuple[str, ...]


def repo_root() -> Path:
    """Find the checkout root without importing project code."""

    for candidate in Path(__file__).resolve().parents:
        if (candidate / "pyproject.toml").is_file() and (candidate / "tests" / "fixtures").is_dir():
            return candidate
    raise DatasetError("could not locate repository root")


def default_config() -> DatasetConfig:
    root = repo_root()
    return DatasetConfig(
        fixture_root=root / "tests" / "fixtures",
        output_root=root / "out" / "dashboard-fixture-dataset",
        dashboard_report_root=root / "tests" / "fixtures" / "dashboard",
    )


def build_dataset(config: DatasetConfig) -> DatasetResult:
    """Write one canonical report for every selected capture fixture."""

    _validate_config(config)
    fixture_cases = _discover_fixture_cases(config)
    _prepare_output_root(config.output_root, replace_existing=config.replace_existing)

    catalog_entries: list[dict[str, str]] = []
    manifest_cases: list[dict[str, Any]] = []
    case_ids: list[str] = []
    for fixture_dir in fixture_cases:
        fixture_id = fixture_dir.name
        case_id = f"{config.case_id_prefix}{fixture_id}"
        _validate_case_id(case_id)
        expected_path = fixture_dir / "expected.json"
        capture_path = _capture_path(fixture_dir)
        evidence = _read_object(expected_path, "expected fixture evidence")
        _validate_evidence(evidence, expected_path)
        actual_capture_sha256 = _sha256_file(capture_path)
        expected_sha256 = _required_string(
            evidence.get("run_identity"), "capture_sha256", expected_path
        )
        if config.validate_capture_sha256 and actual_capture_sha256 != expected_sha256:
            raise DatasetError(
                f"capture SHA-256 does not match run identity for {fixture_id}: {capture_path}"
            )
        report = _build_report(
            evidence,
            case_id=case_id,
            capture_name=capture_path.name,
            source_capture_sha256=expected_sha256,
            generated_at=config.generated_at,
            renderer=config.renderer,
            dependency_versions=config.dependency_versions,
            include_analyst_notes=config.include_analyst_notes,
        )
        report_filename = f"{case_id}.report.json"
        serialized = _json_bytes(report)
        _write_bytes(config.output_root / report_filename, serialized)
        catalog_entries.append({"case_id": case_id, "report": report_filename})
        manifest_cases.append(
            {
                "case_id": case_id,
                "fixture_id": fixture_id,
                "capture": str(capture_path.relative_to(repo_root())),
                "capture_sha256": actual_capture_sha256,
                "run_identity_capture_sha256": expected_sha256,
                "capture_sha256_matches_run_identity": actual_capture_sha256 == expected_sha256,
                "expected_json_sha256": _sha256_file(expected_path),
                "provenance_json_sha256": _optional_sha256(fixture_dir / "provenance.json"),
                "report_sha256": hashlib.sha256(serialized).hexdigest(),
                "risk_score": evidence["posture"]["risk_score"],
                "finding_count": len(evidence["posture"]["prioritized_findings"]),
            }
        )
        case_ids.append(case_id)

    if config.include_dashboard_cases:
        dashboard_entries = _copy_dashboard_cases(config.dashboard_report_root, config.output_root)
        duplicate_ids = {entry["case_id"] for entry in catalog_entries}.intersection(
            entry["case_id"] for entry in dashboard_entries
        )
        if duplicate_ids:
            rendered = ", ".join(sorted(duplicate_ids))
            raise DatasetError(f"dashboard reports duplicate generated case IDs: {rendered}")
        catalog_entries.extend(
            {"case_id": entry["case_id"], "report": entry["report"]}
            for entry in dashboard_entries
        )
        manifest_cases.extend(dashboard_entries)
        case_ids.extend(entry["case_id"] for entry in dashboard_entries)

    catalog_entries.sort(key=lambda item: item["case_id"])
    _write_json(
        config.output_root / "catalog.json",
        {"schema_version": CATALOG_SCHEMA_VERSION, "reports": catalog_entries},
    )
    _write_json(
        config.output_root / "dataset-manifest.json",
        {
            "schema_version": DATASET_SCHEMA_VERSION,
            "generator": "tools/build_dashboard_fixture_dataset.py",
            "generated_at": config.generated_at,
            "fixture_root": str(config.fixture_root),
            "configuration": _config_for_manifest(config),
            "cases": manifest_cases,
            "notes": [
                "Evidence is copied from reviewed capture-fixture expected.json contracts.",
                "The generator does not run Zeek, TShark, or the SecureMail application.",
                "Advisory ML is absent; no advisory output is fabricated for fixture data.",
            ],
        },
    )
    return DatasetResult(output_root=config.output_root, case_ids=tuple(case_ids))


def _copy_dashboard_cases(source_root: Path, output_root: Path) -> list[dict[str, Any]]:
    """Copy the committed dashboard coverage cases into the generated catalog."""

    catalog_path = source_root / "catalog.json"
    catalog = _read_object(catalog_path, "dashboard report catalog")
    if catalog.get("schema_version") != CATALOG_SCHEMA_VERSION:
        raise DatasetError(f"unsupported dashboard report catalog schema: {catalog_path}")
    reports = catalog.get("reports")
    if not isinstance(reports, list):
        raise DatasetError(f"dashboard report catalog has no reports list: {catalog_path}")
    copied: list[dict[str, Any]] = []
    for item in reports:
        if not isinstance(item, dict):
            raise DatasetError(f"dashboard report catalog entry is not an object: {catalog_path}")
        case_id = item.get("case_id")
        filename = item.get("report")
        if not isinstance(case_id, str) or not isinstance(filename, str):
            raise DatasetError(f"dashboard report catalog entry is incomplete: {catalog_path}")
        _validate_case_id(case_id)
        if Path(filename).name != filename or not filename.endswith(".report.json"):
            raise DatasetError(f"dashboard report filename is unsafe: {filename!r}")
        report_path = source_root / filename
        report = _read_object(report_path, "dashboard report")
        manifest = report.get("manifest")
        if report.get("schema_version") != REPORT_SCHEMA_VERSION or not isinstance(manifest, dict):
            raise DatasetError(f"dashboard report is not a canonical report: {report_path}")
        if manifest.get("case_id") != case_id:
            raise DatasetError(f"dashboard report case ID does not match catalog: {report_path}")
        payload = report_path.read_bytes()
        _write_bytes(output_root / filename, payload)
        copied.append(
            {
                "case_id": case_id,
                "report": filename,
                "source_report": str(report_path.relative_to(repo_root())),
                "report_sha256": hashlib.sha256(payload).hexdigest(),
                "risk_score": report["evidence"]["posture"]["risk_score"],
                "finding_count": len(report["evidence"]["posture"]["prioritized_findings"]),
            }
        )
    return copied


def _build_report(
    evidence: dict[str, Any],
    *,
    case_id: str,
    capture_name: str,
    source_capture_sha256: str,
    generated_at: str,
    renderer: dict[str, Any],
    dependency_versions: dict[str, str],
    include_analyst_notes: bool,
) -> dict[str, Any]:
    run_identity = evidence["run_identity"]
    posture = evidence["posture"]
    coverage = posture["coverage"]["overall"]
    incomplete = sum(
        flow.get("reconstruction_quality") == "incomplete" for flow in evidence["flows"]
    )
    conflicting = sum(
        flow.get("reconstruction_quality") == "conflicting" for flow in evidence["flows"]
    )
    not_observable_certificates = sum(
        handshake.get("server_certificate_state") == "not_observable"
        for handshake in evidence["handshakes"]
    )
    notes = [
        f"Fixture-derived evidence for {case_id}; source is the reviewed expected.json contract.",
        "Advisory ML is intentionally absent from this deterministic fixture dataset.",
    ]
    if evidence["capture_preflight"]["truncated_packets_present"]:
        notes.append("Capture contains truncated packets; reconstruction may be incomplete.")
    if incomplete:
        notes.append(f"{incomplete} flow(s) have incomplete TCP reconstruction.")
    if conflicting:
        notes.append(f"{conflicting} flow(s) have conflicting TCP reconstructions.")
    if not_observable_certificates:
        notes.append(
            f"{not_observable_certificates} handshake(s) have certificates that are not observable."
        )
    analyst_notes = (
        [
            "Fixture dataset entry: deterministic findings and observed evidence are retained "
            "exactly from the reviewed test contract."
        ]
        if include_analyst_notes
        else []
    )
    analysis_run_id = f"{case_id}-run"
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "manifest": {
            "schema_version": REPORT_SCHEMA_VERSION,
            "generated_at": generated_at,
            "case_id": case_id,
            "capture_id": source_capture_sha256[:32],
            "analysis_run_id": analysis_run_id,
            "source_capture_sha256": source_capture_sha256,
            "working_copy_sha256": None,
            "working_copy_availability": "unavailable",
            "source_records": [
                {"kind": "case", "identifier": case_id, "availability": "present"},
                {
                    "kind": "capture",
                    "identifier": source_capture_sha256[:32],
                    "availability": "present",
                },
                {"kind": "analysis_run", "identifier": analysis_run_id, "availability": "present"},
            ],
            "artifact_hashes": [
                {"name": capture_name, "sha256": source_capture_sha256, "availability": "present"}
            ],
            "renderer": renderer,
            "signature": {"availability": "unavailable", "algorithm": None, "timestamp": None},
            "posture_summary": {
                "assessment_state": posture["assessment_state"],
                "risk_score": posture["risk_score"],
                "finding_count": len(posture["prioritized_findings"]),
                "unknown_count": coverage["unknown_count"],
                "not_observable_count": coverage["not_observable_count"],
            },
            "timezone": "UTC",
            "random_seed": None,
            "configuration_digest": run_identity["configuration_digest"],
            "analyzer_bundle_digest": run_identity["analyzer_bundle_digest"],
            "policy_profile": run_identity["policy_profile"],
            "policy_pack_version": run_identity["policy_pack_version"],
            "trust_store_digest": run_identity["trust_store_digest"],
            "os_container": None,
            "os_container_availability": "unavailable",
            "dependency_versions": dependency_versions,
        },
        "evidence": evidence,
        "limitations": {
            "truncated_packets_present": evidence["capture_preflight"]["truncated_packets_present"],
            "incomplete_flow_count": incomplete,
            "conflicting_flow_count": conflicting,
            "not_observable_certificate_count": not_observable_certificates,
            "unknown_check_count": coverage["unknown_count"],
            "not_observable_check_count": coverage["not_observable_count"],
            "notes": notes[:32],
        },
        "stage_errors": [],
        "suppressed_findings": [],
        "exceptions": [],
        "advisory": {"present": False, "items": []},
        "analyst_conclusions": {"present": bool(analyst_notes), "notes": analyst_notes},
    }


def _discover_fixture_cases(config: DatasetConfig) -> list[Path]:
    if not config.fixture_root.is_dir():
        raise DatasetError(f"fixture root is not a directory: {config.fixture_root}")
    cases: list[Path] = []
    for expected_path in sorted(config.fixture_root.glob("*/expected.json")):
        fixture_id = expected_path.parent.name
        if _capture_path_or_none(expected_path.parent) is None:
            continue
        if not _matches(fixture_id, config.include) or _matches(fixture_id, config.exclude):
            continue
        cases.append(expected_path.parent)
    if config.max_cases is not None:
        cases = cases[: config.max_cases]
    if not cases:
        raise DatasetError("no capture fixture cases matched the configured selection")
    return cases


def _matches(case_id: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(case_id, pattern) for pattern in patterns)


def _capture_path_or_none(fixture_dir: Path) -> Path | None:
    candidates = [fixture_dir / "capture.pcapng", fixture_dir / "capture.pcap"]
    present = [path for path in candidates if path.is_file()]
    if len(present) > 1:
        raise DatasetError(f"fixture has both PCAP and PCAPNG captures: {fixture_dir}")
    return present[0] if present else None


def _capture_path(fixture_dir: Path) -> Path:
    capture = _capture_path_or_none(fixture_dir)
    if capture is None:
        raise DatasetError(f"fixture has no capture: {fixture_dir}")
    return capture


def _prepare_output_root(output_root: Path, *, replace_existing: bool) -> None:
    if output_root.exists():
        if not output_root.is_dir() or output_root.is_symlink():
            raise DatasetError(f"output root must be a non-symlink directory: {output_root}")
        if any(output_root.iterdir()) and not replace_existing:
            raise DatasetError(
                f"output root is not empty: {output_root}; use --replace to overwrite this dataset"
            )
    else:
        output_root.mkdir(parents=True, exist_ok=False)


def _validate_config(config: DatasetConfig) -> None:
    if not config.case_id_prefix:
        raise DatasetError("case_id_prefix must not be empty")
    if config.max_cases is not None and config.max_cases < 1:
        raise DatasetError("max_cases must be at least one")
    if not config.include:
        raise DatasetError("include must contain at least one pattern")
    if config.include_dashboard_cases and not config.dashboard_report_root.is_dir():
        raise DatasetError(
            f"dashboard report root is not a directory: {config.dashboard_report_root}"
        )
    if not isinstance(config.renderer, dict) or not config.renderer:
        raise DatasetError("renderer must be a non-empty object")
    if not isinstance(config.dependency_versions, dict):
        raise DatasetError("dependency_versions must be an object")


def _validate_case_id(case_id: str) -> None:
    if CASE_ID_PATTERN.fullmatch(case_id) is None:
        raise DatasetError(f"generated case ID is invalid: {case_id!r}")


def _validate_evidence(evidence: dict[str, Any], path: Path) -> None:
    missing = EVIDENCE_KEYS - evidence.keys()
    if missing:
        rendered = ", ".join(sorted(missing))
        raise DatasetError(f"expected fixture evidence is incomplete ({rendered}): {path}")
    if evidence["schema_version"] != "v2":
        raise DatasetError(f"unsupported evidence schema in {path}: {evidence['schema_version']!r}")
    for key in ("run_identity", "capture_preflight", "posture"):
        if not isinstance(evidence[key], dict):
            raise DatasetError(f"expected {key} object in {path}")
    for key in ("flows", "sessions", "handshakes", "certificates", "findings", "policy_checks"):
        if not isinstance(evidence[key], list):
            raise DatasetError(f"expected {key} list in {path}")


def _required_string(value: object, key: str, path: Path) -> str:
    if not isinstance(value, dict) or not isinstance(value.get(key), str):
        raise DatasetError(f"expected {key} string in {path}")
    return value[key]


def _read_object(path: Path, description: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DatasetError(f"could not read {description}: {path}") from exc
    if not isinstance(payload, dict):
        raise DatasetError(f"{description} must be a JSON object: {path}")
    return payload


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _optional_sha256(path: Path) -> str | None:
    return _sha256_file(path) if path.is_file() else None


def _json_bytes(payload: object) -> bytes:
    rendered = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    return rendered.encode("utf-8")


def _write_json(path: Path, payload: object) -> None:
    _write_bytes(path, _json_bytes(payload))


def _write_bytes(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)


def _config_for_manifest(config: DatasetConfig) -> dict[str, Any]:
    payload = asdict(config)
    payload["fixture_root"] = str(config.fixture_root)
    payload["output_root"] = str(config.output_root)
    payload["dashboard_report_root"] = str(config.dashboard_report_root)
    payload["include"] = list(config.include)
    payload["exclude"] = list(config.exclude)
    return payload


def _load_config(path: Path) -> dict[str, Any]:
    return _read_object(path, "dataset configuration")


def _config_from_args(args: argparse.Namespace) -> DatasetConfig:
    defaults = default_config()
    config_file = _load_config(args.config) if args.config is not None else {}
    allowed = set(DatasetConfig.__dataclass_fields__)
    unknown = set(config_file) - allowed
    if unknown:
        raise DatasetError(f"unknown configuration key(s): {', '.join(sorted(unknown))}")
    values: dict[str, Any] = asdict(defaults)
    values.update(config_file)
    for key in ("fixture_root", "output_root", "dashboard_report_root"):
        values[key] = Path(values[key]).expanduser().absolute()
    for key in ("include", "exclude"):
        value = values[key]
        if not isinstance(value, list | tuple) or not all(isinstance(item, str) for item in value):
            raise DatasetError(f"{key} must be an array of strings")
        values[key] = tuple(value)
    if args.fixture_root is not None:
        values["fixture_root"] = args.fixture_root.expanduser().absolute()
    if args.output_root is not None:
        values["output_root"] = args.output_root.expanduser().absolute()
    if args.dashboard_report_root is not None:
        values["dashboard_report_root"] = args.dashboard_report_root.expanduser().absolute()
    if args.case_id_prefix is not None:
        values["case_id_prefix"] = args.case_id_prefix
    if args.generated_at is not None:
        values["generated_at"] = args.generated_at
    if args.include:
        values["include"] = tuple(args.include)
    if args.exclude:
        values["exclude"] = tuple(args.exclude)
    if args.max_cases is not None:
        values["max_cases"] = args.max_cases
    if args.validate_capture_sha256:
        values["validate_capture_sha256"] = True
    if args.no_analyst_notes:
        values["include_analyst_notes"] = False
    if args.no_dashboard_cases:
        values["include_dashboard_cases"] = False
    if args.replace:
        values["replace_existing"] = True
    return DatasetConfig(**values)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, help="JSON configuration file")
    parser.add_argument(
        "--fixture-root", type=Path, help="fixture directory; default: tests/fixtures"
    )
    parser.add_argument("--out", dest="output_root", type=Path, help="catalog output directory")
    parser.add_argument(
        "--dashboard-report-root",
        type=Path,
        help="source directory for committed dashboard coverage reports",
    )
    parser.add_argument("--case-id-prefix", help="prefix applied to every dashboard case ID")
    parser.add_argument("--generated-at", help="RFC 3339 UTC timestamp recorded in every report")
    parser.add_argument("--include", action="append", help="fixture glob to include; repeatable")
    parser.add_argument("--exclude", action="append", help="fixture glob to exclude; repeatable")
    parser.add_argument("--max-cases", type=int, help="maximum selected fixtures, after sorting")
    parser.add_argument(
        "--validate-capture-sha256",
        action="store_true",
        help="fail if capture bytes differ from expected run_identity.capture_sha256",
    )
    parser.add_argument(
        "--no-analyst-notes",
        action="store_true",
        help="omit the clearly labelled fixture-dataset analyst note",
    )
    parser.add_argument(
        "--no-dashboard-cases",
        action="store_true",
        help="exclude the committed dashboard coverage reports from the dataset",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help="allow overwriting generated report and catalog files in a non-empty output directory",
    )
    parser.add_argument(
        "--print-default-config",
        action="store_true",
        help="print the full default JSON configuration and exit",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.print_default_config:
        config = _config_for_manifest(default_config())
        sys.stdout.write(json.dumps(config, indent=2, sort_keys=True) + "\n")
        return 0
    try:
        result = build_dataset(_config_from_args(args))
    except DatasetError as exc:
        sys.stderr.write(f"dashboard fixture dataset: {exc}\n")
        return 1
    sys.stdout.write(f"Wrote {len(result.case_ids)} dashboard cases to {result.output_root}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
