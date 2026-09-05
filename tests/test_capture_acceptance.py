"""HTTP upload of a real fixture capture through sandboxed analysis."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
from tests.support.fixture_harness import repo_root

from securemail.bootstrap import create_api, process_pending_analysis


def test_empty_pcap_upload_produces_html_and_pdf(tmp_path: Path) -> None:
    capture = repo_root() / "tests" / "fixtures" / "empty" / "capture.pcapng"
    payload = capture.read_bytes()
    app = create_api(
        report_root=tmp_path,
        data_root=tmp_path,
        static_dir=Path("/not-built"),
        start_worker=False,
    )
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/analyses",
            files={"file": ("empty.pcapng", payload, "application/octet-stream")},
        )
        assert created.status_code == 202
        run_id = created.json()["run_id"]
        case_id = created.json()["case_id"]
        finished = process_pending_analysis(data_root=tmp_path, report_root=tmp_path)
        assert finished is not None
        status = client.get(f"/api/v1/analyses/{run_id}")
        assert status.json()["status"] == "completed"
        report = client.get(f"/api/v1/analyses/{run_id}/report")
        html = client.get(f"/api/v1/analyses/{run_id}/report.html")
        pdf = client.get(f"/api/v1/analyses/{run_id}/report.pdf")
        catalog = client.get(f"/api/v1/cases/{case_id}/report")
    body = json.loads(report.content)
    assert report.status_code == 200
    assert html.status_code == 200
    assert pdf.status_code == 200
    assert catalog.status_code == 200
    assert catalog.content == report.content
    assert html.headers["content-type"].startswith("text/html")
    assert pdf.content[:4] == b"%PDF"
    assert body["advisory"]["present"] is True
    codes = [item["code"] for item in body["advisory"]["items"]]
    assert "ADVISORY_INSUFFICIENT_HISTORY" in codes
    assert isinstance(body["evidence"]["findings"], list)
    findings = body["evidence"]["findings"]
    assert findings == json.loads(catalog.content)["evidence"]["findings"]
