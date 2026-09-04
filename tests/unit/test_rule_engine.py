"""YAML inline cases are the boundary tests. Engine stays a generic evaluator."""

from datetime import UTC, date, datetime

import pytest

from securemail.adapters.reference_data.policy_packs import load_policy_pack
from securemail.domain.evidence.flow import Flow, ReconstructionQuality, StreamDirection
from securemail.domain.evidence.handshake import (
    CipherSuiteEvidence,
    HandshakeSignatureEvidence,
    HandshakeVisibility,
    KeyExchangeEvidence,
    TlsHandshake,
    TlsVersionEvidence,
    VersionSource,
)
from securemail.domain.evidence.run import EvidenceState, PolicyProfile
from securemail.domain.evidence.session import (
    EmailSession,
    EventSource,
    MailProtocol,
    PayloadEvidence,
    PortHint,
    ProtocolEvent,
    SessionEventKind,
)
from securemail.domain.findings.finding import FindingOutcome
from securemail.domain.policies.rule_engine import (
    EvaluationClock,
    InlineRuleTest,
    PolicyEngineError,
    RuleEvalResult,
    canonical_pack_digest,
    evaluate_inline_test,
    evaluate_policy,
    evaluate_policy_batch,
    resolve_evaluation_clock,
)


def _inline_cases() -> list[tuple[str, str, str, InlineRuleTest]]:
    cases: list[tuple[str, str, str, InlineRuleTest]] = []
    for profile in PolicyProfile:
        pack, _digest = load_policy_pack(profile)
        for rule in pack.rules:
            for test in rule.tests:
                cases.append((profile.value, rule.id, test.id, test))
    return cases


_INLINE_CASES = _inline_cases()


@pytest.mark.parametrize(
    ("profile", "rule_id", "test_id", "test"),
    _INLINE_CASES,
    ids=[f"{profile}:{rule_id}:{test_id}" for profile, rule_id, test_id, _test in _INLINE_CASES],
)
def test_yaml_inline_boundaries(
    profile: str,
    rule_id: str,
    test_id: str,
    test: InlineRuleTest,
) -> None:
    pack, _digest = load_policy_pack(profile)
    rule = next(item for item in pack.rules if item.id == rule_id)
    result = evaluate_inline_test(rule, test)
    expected = test.expected
    if expected == "pass":
        assert result in {RuleEvalResult.PASS, RuleEvalResult.NOT_APPLICABLE}
        return
    assert result.value == expected


def test_canonical_digest_is_stable() -> None:
    first, digest = load_policy_pack(PolicyProfile.IETF_CURRENT)
    assert digest == canonical_pack_digest(first)
    again, again_digest = load_policy_pack(PolicyProfile.IETF_CURRENT)
    assert again_digest == digest
    assert again.version == first.version


def test_historical_clock_uses_capture_start() -> None:
    pack, _digest = load_policy_pack(PolicyProfile.HISTORICAL_AT_CAPTURE)
    assert pack.evaluation_clock is EvaluationClock.CAPTURE_START_TIME
    capture_start = datetime(2018, 6, 1, tzinfo=UTC)
    resolved = resolve_evaluation_clock(
        pack,
        analysis_time=datetime(2026, 9, 4, tzinfo=UTC),
        capture_start_time=capture_start,
    )
    assert resolved == capture_start
    with pytest.raises(PolicyEngineError, match="capture start time unavailable"):
        resolve_evaluation_clock(
            pack,
            analysis_time=datetime(2026, 9, 4, tzinfo=UTC),
            capture_start_time=None,
        )


def _flow(port: int, uid: str = "Ctest") -> Flow:
    return Flow(
        uid=uid,
        orig={"host": "192.0.2.10", "port": 49152},
        resp={"host": "192.0.2.25", "port": port},
        proto="tcp",
        history="ShADadFf",
        conn_state="SF",
        missed_bytes=0,
        orig_bytes=64,
        resp_bytes=64,
        reconstruction_quality=ReconstructionQuality.COMPLETE,
        gap_bytes=0,
        gap_bytes_exact=True,
        evidence_state=EvidenceState.OBSERVED,
    )


def _smtp_session(uid: str = "Ctest") -> EmailSession:
    return EmailSession(
        uid=uid,
        protocol=MailProtocol.SMTP,
        port_hint=PortHint.SMTP,
        payload_evidence=PayloadEvidence.SMTP,
        evidence_state=EvidenceState.OBSERVED,
        events=[
            ProtocolEvent(
                direction=StreamDirection.ORIG,
                kind=SessionEventKind.REQUEST,
                command="EHLO",
                source=EventSource.ZEEK,
            )
        ],
    )


def _handshake(uid: str = "Ctest") -> TlsHandshake:
    return TlsHandshake(
        uid=uid,
        ssl_history="Csxn",
        established=True,
        resumed=False,
        hello_retry_request=False,
        visibility=HandshakeVisibility.FULL,
        version=TlsVersionEvidence(
            selected="TLSv12",
            source=VersionSource.LEGACY_RECORD,
            evidence_state=EvidenceState.OBSERVED,
        ),
        cipher_suite=CipherSuiteEvidence(
            name="TLS_RSA_WITH_AES_128_CBC_SHA",
            code="0x002F",
            evidence_state=EvidenceState.OBSERVED,
        ),
        key_exchange=KeyExchangeEvidence(
            mechanism="RSA",
            evidence_state=EvidenceState.INFERRED,
        ),
        server_certificate_state=EvidenceState.OBSERVED,
        certificate_verify_state=EvidenceState.NOT_OBSERVABLE,
        certificate_verify_signature=HandshakeSignatureEvidence(
            algorithm=None,
            evidence_state=EvidenceState.NOT_OBSERVABLE,
        ),
        evidence_state=EvidenceState.OBSERVED,
    )


def test_smtp_relay_does_not_receive_submission_cleartext_finding() -> None:
    pack, digest = load_policy_pack(PolicyProfile.IETF_CURRENT)
    findings = evaluate_policy(
        pack=pack,
        pack_digest=digest,
        capture_sha256="a" * 64,
        evaluation_time=datetime(2026, 9, 4, tzinfo=UTC),
        flows=[_flow(25)],
        sessions=[_smtp_session()],
        handshakes=[],
        certificates=[],
    )
    codes = {item.code for item in findings}
    assert "MAIL_SUBMISSION_CLEARTEXT" not in codes


def test_smtp_submission_cleartext_is_a_finding() -> None:
    pack, digest = load_policy_pack(PolicyProfile.IETF_CURRENT)
    findings = evaluate_policy(
        pack=pack,
        pack_digest=digest,
        capture_sha256="a" * 64,
        evaluation_time=datetime(2026, 9, 4, tzinfo=UTC),
        flows=[_flow(587)],
        sessions=[_smtp_session()],
        handshakes=[],
        certificates=[],
    )
    codes = {item.code for item in findings}
    assert "MAIL_SUBMISSION_CLEARTEXT" in codes


def test_finding_ids_are_deterministic_and_ordered() -> None:
    pack, digest = load_policy_pack(PolicyProfile.IETF_CURRENT)
    kwargs = {
        "pack": pack,
        "pack_digest": digest,
        "capture_sha256": "b" * 64,
        "evaluation_time": datetime(2026, 9, 4, 12, tzinfo=UTC),
        "flows": [_flow(4433)],
        "sessions": [],
        "handshakes": [_handshake()],
        "certificates": [],
    }
    first = evaluate_policy(**kwargs)
    second = evaluate_policy(**kwargs)
    assert [item.finding_id for item in first] == [item.finding_id for item in second]
    assert first
    assert [item.code for item in first] == sorted(item.code for item in first)
    assert all(
        item.outcome in {FindingOutcome.NEGATIVE, FindingOutcome.INDETERMINATE} for item in first
    )
    assert all(item.policy_pack_version == digest for item in first)


def test_unusable_assertion_is_indeterminate_not_negative() -> None:
    pack, _digest = load_policy_pack(PolicyProfile.IETF_CURRENT)
    rule = next(item for item in pack.rules if item.id == "TLS_NEGOTIATED_TLS10")
    result = evaluate_inline_test(
        rule,
        type(rule.tests[0])(
            id="missing_version",
            at=date(2026, 9, 1),
            values={"handshake.version.evidence_state": "observed"},
            expected="indeterminate",
        ),
    )
    assert result is RuleEvalResult.INDETERMINATE


def test_policy_batch_records_passes_and_excludes_non_applicable() -> None:
    pack, digest = load_policy_pack(PolicyProfile.IETF_CURRENT)
    evaluation = evaluate_policy_batch(
        pack=pack,
        pack_digest=digest,
        capture_sha256="a" * 64,
        evaluation_time=datetime(2026, 9, 4, tzinfo=UTC),
        flows=[_flow(25)],
        sessions=[_smtp_session()],
        handshakes=[],
        certificates=[],
    )
    codes = {item.code for item in evaluation.checks}
    assert "MAIL_SUBMISSION_CLEARTEXT" not in {item.code for item in evaluation.findings}
    assert "MAIL_SUBMISSION_CLEARTEXT" not in codes
    assert "UPGRADE_ACCEPTED_WITHOUT_TLS_TRANSITION" in codes


def test_unusable_where_is_unknown_check_not_a_finding() -> None:
    pack, digest = load_policy_pack(PolicyProfile.IETF_CURRENT)
    evaluation = evaluate_policy_batch(
        pack=pack,
        pack_digest=digest,
        capture_sha256="a" * 64,
        evaluation_time=datetime(2026, 9, 4, tzinfo=UTC),
        flows=[_flow(25)],
        sessions=[_smtp_session()],
        handshakes=[],
        certificates=[],
    )
    upgrade = [
        item for item in evaluation.checks if item.code == "UPGRADE_ACCEPTED_WITHOUT_TLS_TRANSITION"
    ]
    assert upgrade
    assert all(item.outcome.value == "unknown" for item in upgrade)
    assert "UPGRADE_ACCEPTED_WITHOUT_TLS_TRANSITION" not in {
        item.code for item in evaluation.findings
    }


def test_unusable_assertion_emits_indeterminate_finding_and_coverage() -> None:
    pack, digest = load_policy_pack(PolicyProfile.IETF_CURRENT)
    handshake = _handshake()
    handshake = handshake.model_copy(
        update={"version": handshake.version.model_copy(update={"selected": None})}
    )
    evaluation = evaluate_policy_batch(
        pack=pack,
        pack_digest=digest,
        capture_sha256="a" * 64,
        evaluation_time=datetime(2026, 9, 4, tzinfo=UTC),
        flows=[_flow(4433)],
        sessions=[],
        handshakes=[handshake],
        certificates=[],
    )
    tls10_checks = [item for item in evaluation.checks if item.code == "TLS_NEGOTIATED_TLS10"]
    tls10_findings = [item for item in evaluation.findings if item.code == "TLS_NEGOTIATED_TLS10"]
    assert tls10_checks
    assert all(item.outcome.value in {"unknown", "not_observable"} for item in tls10_checks)
    assert tls10_findings
    assert all(item.outcome is FindingOutcome.INDETERMINATE for item in tls10_findings)
