"""HTML renderer: autoescape, hostile-input handling, finding-code fidelity."""

from __future__ import annotations

import json
import re

from tests.support.fixture_harness import load_golden_report, repo_root

from securemail.adapters.reports.html_renderer import (
    autoescape_enabled,
    forensic_text,
    render_html,
    template_path,
    template_sha256,
)
from securemail.domain.reports.schema import AdvisoryItem, AdvisorySection, CanonicalReport


def _html() -> str:
    report = CanonicalReport.model_validate(load_golden_report())
    return render_html(report.model_dump(mode="json"))


def _provenance() -> dict[str, object]:
    path = repo_root() / "tests" / "fixtures" / "reports" / "provenance.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_autoescape_is_enabled() -> None:
    assert autoescape_enabled() is True


def test_template_has_no_safe_bypass() -> None:
    text = template_path().read_text(encoding="utf-8")
    assert "|safe" not in text
    assert "autoescape" not in text.lower() or "autoescape=False" not in text


def test_template_hash_matches_provenance() -> None:
    assert template_sha256() == _provenance()["template_sha256"]


def test_html_is_deterministic() -> None:
    report = CanonicalReport.model_validate(load_golden_report())
    payload = report.model_dump(mode="json")
    assert render_html(payload) == render_html(payload)


def test_hostile_banner_is_escaped() -> None:
    html = _html()
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "\\u0007" in html
    assert "\\u0000" in html
    assert "\\u202E" in html
    assert "\u0007" not in html
    assert "\u202e" not in html


def test_finding_codes_appear() -> None:
    html = _html()
    codes = _provenance()["finding_codes"]
    assert isinstance(codes, list)
    for code in codes:
        assert str(code) in html


def test_no_network_backed_resources() -> None:
    html = _html()
    assert "http://" not in html
    assert "https://" not in html
    assert "url('file:" not in html
    assert re.search(r"src\s*=\s*['\"]https?:", html) is None
    assert "data:font/ttf;base64," in html


def test_forensic_text_returns_plain_str() -> None:
    result = forensic_text("<x>\u0001")
    assert result == "<x>\\u0001"
    assert type(result) is str


def test_four_regions_are_labeled() -> None:
    html = _html()
    assert "Observed facts" in html
    assert "Deterministic conclusions" in html
    assert "Advisory / ML" in html
    assert "Analyst conclusions" in html
    assert "No advisory section" in html


def test_advisory_items_render_separately_from_findings() -> None:
    report = CanonicalReport.model_validate(load_golden_report())
    updated = report.model_copy(
        update={
            "advisory": AdvisorySection(
                present=True,
                items=[
                    AdvisoryItem(
                        code="ADVISORY_TLS_VERSION_SHIFT",
                        reason=(
                            "tls10_share rose versus this endpoint's trailing median; "
                            "field handshake.version.selected."
                        ),
                    )
                ],
            )
        }
    )
    html = render_html(updated.model_dump(mode="json"))
    assert "ADVISORY_TLS_VERSION_SHIFT" in html
    assert "handshake.version.selected" in html
    assert "No advisory section" not in html
    for code in _provenance()["finding_codes"]:
        assert str(code) in html
