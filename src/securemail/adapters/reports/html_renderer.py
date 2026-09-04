"""Presentation sanitization and Jinja2 HTML rendering for canonical reports."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from securemail.domain.reports.schema import FontResource, RendererManifest

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
_FONTS_DIR = Path(__file__).resolve().parent / "fonts"
_TEMPLATE_NAME = "report.html.j2"

# C0/C1 controls plus Unicode bidi overrides/isolates. Presentation only.
_BIDI_CODEPOINTS = frozenset({0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)})

_STATE_LABELS = {
    "observed": "OBS",
    "verified": "VER",
    "inferred": "INF",
    "incomplete": "INC",
    "conflicting": "CNF",
    "not_observable": "NOB",
    "indeterminate": "IND",
}

_STATE_TITLES = {
    "observed": "Observed",
    "verified": "Verified",
    "inferred": "Inferred",
    "incomplete": "Incomplete",
    "conflicting": "Conflicting",
    "not_observable": "Not observable",
    "indeterminate": "Indeterminate",
}


@dataclass(frozen=True, slots=True)
class BundledFont:
    filename: str
    family: str
    weight: int
    style: Literal["normal", "italic"]


BUNDLED_FONTS: tuple[BundledFont, ...] = (
    BundledFont("NotoSans-Regular.ttf", "Noto Sans", 400, "normal"),
    BundledFont("NotoSans-Bold.ttf", "Noto Sans", 700, "normal"),
    BundledFont("NotoSansMono-Regular.ttf", "Noto Sans Mono", 400, "normal"),
)


class HtmlRenderError(ValueError):
    """Raised when the HTML report cannot be rendered."""


def forensic_text(value: object) -> str:
    """Replace prohibited controls/bidi with visible \\uXXXX. Returns a plain str."""

    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    out: list[str] = []
    for char in text:
        code = ord(char)
        if code < 32 or (127 <= code <= 159) or code in _BIDI_CODEPOINTS:
            out.append(f"\\u{code:04X}")
        else:
            out.append(char)
    return "".join(out)


def template_path() -> Path:
    return _TEMPLATES_DIR / _TEMPLATE_NAME


def template_sha256() -> str:
    return hashlib.sha256(template_path().read_bytes()).hexdigest()


def font_resources() -> list[FontResource]:
    resources: list[FontResource] = []
    for spec in BUNDLED_FONTS:
        path = _FONTS_DIR / spec.filename
        if not path.is_file():
            raise HtmlRenderError(f"bundled font missing: {spec.filename}")
        resources.append(
            FontResource(
                filename=spec.filename,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                family=spec.family,
                weight=spec.weight,
                style=spec.style,
            )
        )
    return resources


def renderer_manifest(*, pdf_renderer_version: str) -> RendererManifest:
    return RendererManifest(
        pdf_renderer_version=pdf_renderer_version,
        template_sha256=template_sha256(),
        fonts=font_resources(),
    )


def _font_data_uri(filename: str) -> str:
    path = _FONTS_DIR / filename
    if not path.is_file():
        raise HtmlRenderError(f"bundled font missing: {filename}")
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:font/ttf;base64,{encoded}"


def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=True,
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["forensic_text"] = forensic_text
    env.filters["short_hash"] = lambda value: str(value)[:12] if value else ""
    env.filters["state_label"] = lambda value: _STATE_LABELS.get(str(value), str(value).upper()[:3])
    env.filters["state_title"] = lambda value: _STATE_TITLES.get(str(value), str(value))
    return env


def _percent(part: int, whole: int) -> float:
    if whole <= 0:
        return 0.0
    return round(100.0 * part / whole, 1)


def _coverage_bar(
    counts: Mapping[str, Any], *, width: int = 360, height: int = 16
) -> dict[str, Any]:
    applicable = int(counts.get("applicable_count") or 0)
    segments = [
        ("pass", int(counts.get("passed_count") or 0), "#215c38"),
        ("fail", int(counts.get("failed_count") or 0), "#8b1e1e"),
        ("unknown", int(counts.get("unknown_count") or 0), "#6b5a2a"),
        ("not_observable", int(counts.get("not_observable_count") or 0), "#3d4a5c"),
    ]
    x = 0.0
    drawn: list[dict[str, Any]] = []
    for name, count, color in segments:
        if applicable <= 0 or count <= 0:
            continue
        w = width * (count / applicable)
        drawn.append(
            {
                "name": name,
                "count": count,
                "percent": _percent(count, applicable),
                "x": round(x, 2),
                "width": round(w, 2),
                "color": color,
            }
        )
        x += w
    return {
        "width": width,
        "height": height,
        "applicable": applicable,
        "segments": drawn,
        "empty": applicable == 0,
    }


def _score_bar(components: Mapping[str, Any]) -> list[dict[str, Any]]:
    caps = {
        "severity": 50,
        "confidence": 20,
        "exposure": 10,
        "recurrence": 10,
        "asset_criticality": 5,
        "blast_radius": 5,
    }
    bars: list[dict[str, Any]] = []
    for name, cap in caps.items():
        value = int(components.get(name) or 0)
        bars.append(
            {
                "name": name.replace("_", " "),
                "value": value,
                "cap": cap,
                "percent": _percent(value, cap),
            }
        )
    return bars


def _upgrade_steps(state: str | None) -> list[dict[str, Any]]:
    order = [
        "advertised",
        "requested",
        "accepted",
        "tls_established",
        "plaintext_fallback",
        "violation",
    ]
    terminal = {
        "tls_established",
        "plaintext_fallback",
        "violation",
    }
    reached = True
    steps: list[dict[str, Any]] = []
    for name in order:
        is_current = state == name
        if name in terminal and not is_current and state in terminal:
            status = "skipped"
        elif is_current:
            status = "current"
        elif reached:
            status = "reached"
        else:
            status = "pending"
        if is_current:
            reached = False
        steps.append({"name": name.replace("_", " "), "status": status})
        if is_current and name in terminal:
            reached = False
    return steps


def _handshake_by_uid(evidence: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {str(item["uid"]): item for item in evidence.get("handshakes") or [] if "uid" in item}


def _session_by_uid(evidence: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {str(item["uid"]): item for item in evidence.get("sessions") or [] if "uid" in item}


def _flow_by_uid(evidence: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {str(item["uid"]): item for item in evidence.get("flows") or [] if "uid" in item}


def _certs_by_uid(evidence: Mapping[str, Any]) -> dict[str, list[Mapping[str, Any]]]:
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for cert in evidence.get("certificates") or []:
        grouped.setdefault(str(cert["uid"]), []).append(cert)
    for uid, certs in grouped.items():
        grouped[uid] = sorted(certs, key=lambda item: int(item.get("chain_index") or 0))
    return grouped


def _lineage_rows(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    evidence = payload["evidence"]
    flows = _flow_by_uid(evidence)
    sessions = _session_by_uid(evidence)
    handshakes = _handshake_by_uid(evidence)
    certs = _certs_by_uid(evidence)
    rows: list[dict[str, Any]] = []
    for finding in evidence["posture"]["prioritized_findings"]:
        uid = None
        for ref in finding.get("evidence_references") or []:
            if ref.get("record_type") in {"session", "handshake", "flow", "certificate"}:
                uid = ref.get("record_key")
                if uid:
                    break
        session = sessions.get(str(uid)) if uid else None
        flow = flows.get(str(uid)) if uid else None
        handshake = handshakes.get(str(uid)) if uid else None
        chain = certs.get(str(uid), []) if uid else []
        rows.append(
            {
                "code": finding["code"],
                "endpoint": finding["affected_endpoint"],
                "basis_state": finding["basis_state"],
                "capture": payload["manifest"]["source_capture_sha256"][:12],
                "flow": None if flow is None else flow["uid"],
                "flow_quality": None if flow is None else flow["reconstruction_quality"],
                "session_protocol": None if session is None else session.get("protocol"),
                "session_state": None if session is None else session.get("evidence_state"),
                "tls_version": None
                if handshake is None
                else (handshake.get("version") or {}).get("selected"),
                "cert_state": None
                if handshake is None
                else handshake.get("server_certificate_state"),
                "cert_count": len(chain),
            }
        )
    return rows


def _starttls_timelines(evidence: Mapping[str, Any]) -> list[dict[str, Any]]:
    timelines: list[dict[str, Any]] = []
    for session in evidence.get("sessions") or []:
        upgrade = session.get("explicit_upgrade")
        if not upgrade:
            continue
        timelines.append(
            {
                "uid": session["uid"],
                "protocol": session.get("protocol"),
                "state": upgrade.get("state"),
                "evidence_state": upgrade.get("evidence_state"),
                "downgrade_consistent": upgrade.get("downgrade_consistent"),
                "steps": _upgrade_steps(upgrade.get("state")),
            }
        )
    return timelines


def _handshake_timelines(evidence: Mapping[str, Any]) -> list[dict[str, Any]]:
    timelines: list[dict[str, Any]] = []
    for handshake in evidence.get("handshakes") or []:
        messages = handshake.get("messages") or []
        width = max(160, 28 + len(messages) * 92)
        timelines.append(
            {
                "uid": handshake["uid"],
                "version": (handshake.get("version") or {}).get("selected"),
                "visibility": handshake.get("visibility"),
                "established": handshake.get("established"),
                "server_certificate_state": handshake.get("server_certificate_state"),
                "width": width,
                "messages": [
                    {
                        "kind": message["kind"].replace("_", " "),
                        "direction": message["direction"],
                        "state": message["evidence_state"],
                        "x": 16 + index * 92,
                    }
                    for index, message in enumerate(messages)
                ],
            }
        )
    return timelines


def _certificate_chains(evidence: Mapping[str, Any]) -> list[dict[str, Any]]:
    chains: list[dict[str, Any]] = []
    for uid, certs in _certs_by_uid(evidence).items():
        chains.append(
            {
                "uid": uid,
                "certs": [
                    {
                        "chain_index": cert.get("chain_index"),
                        "position": (
                            "leaf" if int(cert.get("chain_index") or 0) == 0 else "issuer"
                        ),
                        "subject": cert.get("subject") or "(unparsed)",
                        "issuer": cert.get("issuer") or "(unparsed)",
                        "role": cert.get("role"),
                        "evidence_state": cert.get("evidence_state"),
                        "public_key": " ".join(
                            part
                            for part in (
                                cert.get("public_key_algorithm"),
                                str(cert["public_key_size"])
                                if cert.get("public_key_size") is not None
                                else None,
                                cert.get("public_key_curve"),
                            )
                            if part
                        ),
                    }
                    for cert in certs
                ],
            }
        )
    return chains


def _finding_codes(payload: Mapping[str, Any]) -> list[str]:
    codes: list[str] = []
    seen: set[str] = set()
    for finding in payload["evidence"].get("findings") or []:
        code = str(finding["code"])
        if code not in seen:
            seen.add(code)
            codes.append(code)
    for finding in payload["evidence"]["posture"]["prioritized_findings"]:
        code = str(finding["code"])
        if code not in seen:
            seen.add(code)
            codes.append(code)
    return codes


def build_view(payload: Mapping[str, Any]) -> dict[str, Any]:
    evidence = payload["evidence"]
    coverage = evidence["posture"]["coverage"]
    overall = coverage["overall"]
    risk = evidence["posture"]["risk_score"]
    return {
        "coverage_overall": _coverage_bar(overall),
        "coverage_protocols": [
            {"name": name, "bar": _coverage_bar(counts), "counts": counts}
            for name, counts in (coverage.get("by_protocol") or {}).items()
        ],
        "coverage_categories": [
            {"name": name, "bar": _coverage_bar(counts), "counts": counts}
            for name, counts in (coverage.get("by_category") or {}).items()
        ],
        "score_bars": [
            {"finding": finding, "bars": _score_bar(finding.get("components") or {})}
            for finding in evidence["posture"]["prioritized_findings"]
        ],
        "lineage": _lineage_rows(payload),
        "starttls": _starttls_timelines(evidence),
        "handshakes": _handshake_timelines(evidence),
        "chains": _certificate_chains(evidence),
        "finding_codes": _finding_codes(payload),
        "risk_score": risk,
        "risk_percent": 0 if risk is None else risk,
        "risk_available": risk is not None,
        "font_faces": [
            {
                "family": spec.family,
                "weight": spec.weight,
                "style": spec.style,
                "uri": _font_data_uri(spec.filename),
            }
            for spec in BUNDLED_FONTS
        ],
    }


def render_html(payload: Mapping[str, Any]) -> str:
    """Render one self-contained HTML document from the canonical JSON object."""

    template = _environment().get_template(_TEMPLATE_NAME)
    return template.render(report=payload, view=build_view(payload))


def autoescape_enabled() -> bool:
    return bool(_environment().autoescape)
