"""Assemble the hand-reviewed Step 9 golden report from typed domain models."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, date, datetime
from pathlib import Path

from securemail.adapters.reports.canonical_json import canonicalize, sha256_digest
from securemail.adapters.reports.html_renderer import font_resources, template_sha256
from securemail.adapters.reports.pdf_renderer import weasyprint_version
from securemail.domain.evidence.certificate import (
    CertificateEvidence,
    CertificateRole,
    CertificateValidation,
    ReferenceIdentitySource,
    RevocationStatus,
)
from securemail.domain.evidence.flow import (
    ByteRange,
    Flow,
    FlowEndpoint,
    ReconstructionQuality,
    ReconstructionReasonCode,
    StreamDirection,
)
from securemail.domain.evidence.handshake import (
    CipherSuiteEvidence,
    HandshakeMessage,
    HandshakeMessageKind,
    HandshakeSignatureEvidence,
    HandshakeVisibility,
    KeyExchangeEvidence,
    TlsHandshake,
    TlsVersionEvidence,
    VersionSource,
)
from securemail.domain.evidence.run import (
    AnalysisRun,
    CapturePreflight,
    EvidenceDocument,
    EvidenceState,
    PolicyProfile,
)
from securemail.domain.evidence.session import (
    EmailSession,
    EventSource,
    ExplicitUpgrade,
    ImplicitTls,
    MailProtocol,
    PayloadEvidence,
    PortHint,
    ProtocolEvent,
    SessionEventKind,
    UpgradeState,
)
from securemail.domain.findings.dedup import OccurrenceRef
from securemail.domain.findings.finding import (
    EvidenceRecordType,
    EvidenceReference,
    Finding,
    FindingOutcome,
    FindingSeverity,
)
from securemail.domain.findings.posture import (
    CheckCategory,
    CoverageProtocol,
    PolicyCheck,
    PolicyCheckOutcome,
    ScoredEndpointFinding,
    build_posture,
)
from securemail.domain.findings.scoring import (
    AssetCriticality,
    BlastRadius,
    ExposureClass,
    ScoreComponents,
)
from securemail.domain.reports.schema import (
    AdvisorySection,
    AnalystSection,
    ArtifactHash,
    Availability,
    CanonicalReport,
    CaptureLimitations,
    PostureSummary,
    RendererManifest,
    ReportManifest,
    SignatureMetadata,
    SourceRecord,
    SourceRecordKind,
    canonical_report_json_schema,
)

HERE = Path(__file__).resolve().parent
HOSTILE_BANNER = "220 mail.example<script>alert(1)</script>\u0007\u0000\u202eON.example"
PACK = "c" * 64
CAPTURE = "a" * 64
BUNDLE = "b" * 64
CONFIG = "d" * 64
TRUST = "e" * 64
WHEN = datetime(2026, 9, 4, 12, 0, 0, tzinfo=UTC)
EFFECTIVE = date(2018, 1, 1)


def _hid(n: int) -> str:
    return hashlib.sha256(f"golden-finding-{n}".encode()).hexdigest()


def _check(n: int) -> str:
    return hashlib.sha256(f"golden-check-{n}".encode()).hexdigest()


def _finding(
    n: int,
    *,
    code: str,
    uid: str,
    endpoint: str,
    severity: FindingSeverity,
    basis: EvidenceState,
    title: str,
    record_type: EvidenceRecordType,
    field_path: str,
    frame: int | None = None,
) -> Finding:
    return Finding(
        finding_id=_hid(n),
        code=code,
        outcome=FindingOutcome.NEGATIVE
        if basis not in {EvidenceState.INDETERMINATE, EvidenceState.NOT_OBSERVABLE}
        else FindingOutcome.INDETERMINATE,
        title=title,
        rationale=f"Golden-report {code} with basis_state={basis.value}.",
        standards=["RFC 0"],
        remediation_id="rem.golden",
        severity=severity,
        evaluation_state=EvidenceState.VERIFIED,
        basis_state=basis,
        policy_profile=PolicyProfile.IETF_CURRENT.value,
        policy_pack_version=PACK,
        rule_effective_from=EFFECTIVE,
        policy_evaluation_time=WHEN,
        affected_endpoint=endpoint,
        evidence_references=[
            EvidenceReference(
                record_type=record_type,
                record_key=uid,
                field_path=field_path,
                evidence_state=basis,
                frame_number=frame,
            )
        ],
    )


def _scored(
    finding: Finding,
    *,
    score: int,
    components: ScoreComponents,
    exposure: ExposureClass,
    criticality: AssetCriticality,
    blast: BlastRadius,
) -> ScoredEndpointFinding:
    return ScoredEndpointFinding(
        finding_id=finding.finding_id,
        code=finding.code,
        outcome=finding.outcome,
        title=finding.title,
        rationale=finding.rationale,
        standards=list(finding.standards),
        remediation_id=finding.remediation_id,
        severity=finding.severity,
        evaluation_state=finding.evaluation_state,
        basis_state=finding.basis_state,
        policy_profile=finding.policy_profile,
        policy_pack_version=finding.policy_pack_version,
        rule_effective_from=finding.rule_effective_from,
        policy_evaluation_time=finding.policy_evaluation_time,
        affected_endpoint=finding.affected_endpoint,
        recurrence_count=1,
        unique_occurrences=1,
        contributing_finding_ids=[finding.finding_id],
        contributing_occurrences=[
            OccurrenceRef(
                finding_id=finding.finding_id,
                record_type=finding.evidence_references[0].record_type,
                record_key=finding.evidence_references[0].record_key,
                session_uid=finding.evidence_references[0].record_key,
            )
        ],
        evidence_references=list(finding.evidence_references),
        score=score,
        components=components,
        exposure=exposure,
        asset_criticality=criticality,
        blast_radius=blast,
    )


def build_canonical_report() -> CanonicalReport:
    findings = [
        _finding(
            1,
            code="TLS_NEGOTIATED_TLS10",
            uid="CTrunc",
            endpoint="192.0.2.10:25",
            severity=FindingSeverity.HIGH,
            basis=EvidenceState.VERIFIED,
            title="TLS 1.0 negotiated",
            record_type=EvidenceRecordType.HANDSHAKE,
            field_path="version.selected",
            frame=6,
        ),
        _finding(
            2,
            code="TLS_CIPHER_CBC",
            uid="CSmtp",
            endpoint="192.0.2.11:587",
            severity=FindingSeverity.MEDIUM,
            basis=EvidenceState.OBSERVED,
            title="CBC cipher suite negotiated",
            record_type=EvidenceRecordType.HANDSHAKE,
            field_path="cipher_suite.name",
            frame=8,
        ),
        _finding(
            3,
            code="CERT_EXPIRED_AT_CAPTURE",
            uid="CSmtp",
            endpoint="192.0.2.11:587",
            severity=FindingSeverity.LOW,
            basis=EvidenceState.INFERRED,
            title="Certificate expired at capture time",
            record_type=EvidenceRecordType.CERTIFICATE,
            field_path="valid_at_capture_time",
        ),
        _finding(
            4,
            code="MAIL_STARTTLS_PLAINTEXT_FALLBACK",
            uid="CTrunc",
            endpoint="192.0.2.10:25",
            severity=FindingSeverity.MEDIUM,
            basis=EvidenceState.INCOMPLETE,
            title="STARTTLS plaintext fallback",
            record_type=EvidenceRecordType.SESSION,
            field_path="explicit_upgrade.state",
            frame=4,
        ),
        _finding(
            5,
            code="TCP_RECONSTRUCTION_CONFLICTING",
            uid="CConf",
            endpoint="192.0.2.12:993",
            severity=FindingSeverity.INFORMATIONAL,
            basis=EvidenceState.CONFLICTING,
            title="Conflicting TCP reconstruction",
            record_type=EvidenceRecordType.FLOW,
            field_path="reconstruction_quality",
        ),
        _finding(
            6,
            code="TLS_FORWARD_SECRECY_INDETERMINATE",
            uid="CTls13",
            endpoint="192.0.2.13:465",
            severity=FindingSeverity.INFORMATIONAL,
            basis=EvidenceState.INDETERMINATE,
            title="Forward secrecy indeterminate",
            record_type=EvidenceRecordType.HANDSHAKE,
            field_path="key_exchange.mechanism",
        ),
        _finding(
            7,
            code="CERT_TLS13_NOT_OBSERVABLE",
            uid="CTls13",
            endpoint="192.0.2.13:465",
            severity=FindingSeverity.INFORMATIONAL,
            basis=EvidenceState.NOT_OBSERVABLE,
            title="TLS 1.3 certificate not observable",
            record_type=EvidenceRecordType.HANDSHAKE,
            field_path="server_certificate_state",
        ),
    ]
    scored = [
        _scored(
            findings[0],
            score=90,
            components=ScoreComponents(
                severity=50,
                confidence=20,
                exposure=10,
                recurrence=0,
                asset_criticality=5,
                blast_radius=5,
            ),
            exposure=ExposureClass.PUBLIC,
            criticality=AssetCriticality.CRITICAL,
            blast=BlastRadius.ORGANIZATION,
        ),
        _scored(
            findings[1],
            score=50,
            components=ScoreComponents(
                severity=30,
                confidence=16,
                exposure=2,
                recurrence=0,
                asset_criticality=1,
                blast_radius=1,
            ),
            exposure=ExposureClass.ISOLATED,
            criticality=AssetCriticality.LOW,
            blast=BlastRadius.SINGLE_ENDPOINT,
        ),
        _scored(
            findings[3],
            score=45,
            components=ScoreComponents(
                severity=30,
                confidence=6,
                exposure=5,
                recurrence=0,
                asset_criticality=3,
                blast_radius=1,
            ),
            exposure=ExposureClass.INTERNAL,
            criticality=AssetCriticality.MEDIUM,
            blast=BlastRadius.SINGLE_ENDPOINT,
        ),
        _scored(
            findings[2],
            score=42,
            components=ScoreComponents(
                severity=15,
                confidence=12,
                exposure=8,
                recurrence=0,
                asset_criticality=4,
                blast_radius=3,
            ),
            exposure=ExposureClass.PARTNER,
            criticality=AssetCriticality.HIGH,
            blast=BlastRadius.MULTI_ASSET,
        ),
        _scored(
            findings[4],
            score=10,
            components=ScoreComponents(
                severity=0,
                confidence=3,
                exposure=4,
                recurrence=0,
                asset_criticality=2,
                blast_radius=1,
            ),
            exposure=ExposureClass.UNKNOWN,
            criticality=AssetCriticality.UNKNOWN,
            blast=BlastRadius.UNKNOWN,
        ),
        _scored(
            findings[5],
            score=9,
            components=ScoreComponents(
                severity=0,
                confidence=2,
                exposure=4,
                recurrence=0,
                asset_criticality=2,
                blast_radius=1,
            ),
            exposure=ExposureClass.UNKNOWN,
            criticality=AssetCriticality.UNKNOWN,
            blast=BlastRadius.UNKNOWN,
        ),
        _scored(
            findings[6],
            score=7,
            components=ScoreComponents(
                severity=0,
                confidence=0,
                exposure=4,
                recurrence=0,
                asset_criticality=2,
                blast_radius=1,
            ),
            exposure=ExposureClass.UNKNOWN,
            criticality=AssetCriticality.UNKNOWN,
            blast=BlastRadius.UNKNOWN,
        ),
    ]
    checks = [
        PolicyCheck(
            check_id=_check(1),
            code="TLS_NEGOTIATED_TLS10",
            category=CheckCategory.TLS_HANDSHAKE,
            protocol=CoverageProtocol.SMTP,
            affected_endpoint="192.0.2.10:25",
            record_type=EvidenceRecordType.HANDSHAKE,
            record_key="CTrunc",
            outcome=PolicyCheckOutcome.FAIL,
            evidence_state=EvidenceState.VERIFIED,
            title="TLS 1.0 negotiated",
        ),
        PolicyCheck(
            check_id=_check(2),
            code="TLS_CIPHER_CBC",
            category=CheckCategory.TLS_HANDSHAKE,
            protocol=CoverageProtocol.SMTP,
            affected_endpoint="192.0.2.11:587",
            record_type=EvidenceRecordType.HANDSHAKE,
            record_key="CSmtp",
            outcome=PolicyCheckOutcome.FAIL,
            evidence_state=EvidenceState.OBSERVED,
            title="CBC cipher suite negotiated",
        ),
        PolicyCheck(
            check_id=_check(3),
            code="TLS_CIPHER_NULL",
            category=CheckCategory.TLS_HANDSHAKE,
            protocol=CoverageProtocol.SMTP,
            affected_endpoint="192.0.2.11:587",
            record_type=EvidenceRecordType.HANDSHAKE,
            record_key="CSmtp",
            outcome=PolicyCheckOutcome.PASS,
            evidence_state=EvidenceState.OBSERVED,
            title="NULL cipher suite negotiated",
        ),
        PolicyCheck(
            check_id=_check(4),
            code="MAIL_STARTTLS_ADVERTISED",
            category=CheckCategory.MAIL_PROTOCOL,
            protocol=CoverageProtocol.SMTP,
            affected_endpoint="192.0.2.11:587",
            record_type=EvidenceRecordType.SESSION,
            record_key="CSmtp",
            outcome=PolicyCheckOutcome.PASS,
            evidence_state=EvidenceState.OBSERVED,
            title="STARTTLS advertised",
        ),
        PolicyCheck(
            check_id=_check(5),
            code="CERT_REVOCATION",
            category=CheckCategory.CERTIFICATE,
            protocol=CoverageProtocol.SMTP,
            affected_endpoint="192.0.2.11:587",
            record_type=EvidenceRecordType.CERTIFICATE,
            record_key="CSmtp",
            outcome=PolicyCheckOutcome.UNKNOWN,
            evidence_state=EvidenceState.INDETERMINATE,
            title="Revocation status",
        ),
        PolicyCheck(
            check_id=_check(6),
            code="CERT_CHAIN_VALID",
            category=CheckCategory.CERTIFICATE,
            protocol=CoverageProtocol.IMAP,
            affected_endpoint="192.0.2.13:465",
            record_type=EvidenceRecordType.HANDSHAKE,
            record_key="CTls13",
            outcome=PolicyCheckOutcome.NOT_OBSERVABLE,
            evidence_state=EvidenceState.NOT_OBSERVABLE,
            title="TLS 1.3 certificate chain",
        ),
        PolicyCheck(
            check_id=_check(7),
            code="TCP_RECONSTRUCTION",
            category=CheckCategory.TRANSPORT,
            protocol=CoverageProtocol.IMAP,
            affected_endpoint="192.0.2.12:993",
            record_type=EvidenceRecordType.FLOW,
            record_key="CConf",
            outcome=PolicyCheckOutcome.UNKNOWN,
            evidence_state=EvidenceState.CONFLICTING,
            title="TCP reconstruction quality",
        ),
        PolicyCheck(
            check_id=_check(8),
            code="IMPLICIT_TLS_CORRELATED",
            category=CheckCategory.MAIL_PROTOCOL,
            protocol=CoverageProtocol.IMAP,
            affected_endpoint="192.0.2.12:993",
            record_type=EvidenceRecordType.SESSION,
            record_key="CConf",
            outcome=PolicyCheckOutcome.PASS,
            evidence_state=EvidenceState.OBSERVED,
            title="Implicit TLS correlated",
        ),
    ]
    posture = build_posture(scored, checks)
    evidence = EvidenceDocument(
        run_identity=AnalysisRun(
            capture_sha256=CAPTURE,
            analyzer_bundle_digest=BUNDLE,
            normalization_schema_version="v1",
            configuration_digest=CONFIG,
            analysis_time=WHEN,
            policy_profile=PolicyProfile.IETF_CURRENT,
            policy_pack_version=PACK,
            trust_store_digest=TRUST,
        ),
        capture_preflight=CapturePreflight(
            packet_count=48,
            file_time_precision="nanosecond",
            packet_size_limit=96,
            packet_size_limit_min_inferred=96,
            packet_size_limit_max_inferred=96,
            truncated_packets_present=True,
            original_packet_bytes=12000,
            capture_duration_seconds=1.25,
            capture_start_time=WHEN,
        ),
        flows=[
            Flow(
                uid="CSmtp",
                orig=FlowEndpoint(host="198.51.100.10", port=40100),
                resp=FlowEndpoint(host="192.0.2.11", port=587),
                proto="tcp",
                history="ShADadFf",
                conn_state="SF",
                missed_bytes=0,
                orig_bytes=800,
                resp_bytes=2400,
                reconstruction_quality=ReconstructionQuality.COMPLETE,
                gap_bytes=0,
                evidence_state=EvidenceState.OBSERVED,
            ),
            Flow(
                uid="CTrunc",
                orig=FlowEndpoint(host="198.51.100.11", port=40101),
                resp=FlowEndpoint(host="192.0.2.10", port=25),
                proto="tcp",
                history="ShAD",
                conn_state="S1",
                missed_bytes=120,
                orig_bytes=200,
                resp_bytes=80,
                reconstruction_quality=ReconstructionQuality.INCOMPLETE,
                reason_code=ReconstructionReasonCode.SNAPLEN_TRUNCATION,
                gap_bytes=120,
                gap_bytes_exact=True,
                evidence_state=EvidenceState.INCOMPLETE,
            ),
            Flow(
                uid="CConf",
                orig=FlowEndpoint(host="198.51.100.12", port=40102),
                resp=FlowEndpoint(host="192.0.2.12", port=993),
                proto="tcp",
                history="ShADad",
                conn_state="S1",
                missed_bytes=0,
                orig_bytes=900,
                resp_bytes=1100,
                reconstruction_quality=ReconstructionQuality.CONFLICTING,
                reason_code=ReconstructionReasonCode.OVERLAPPING_RETRANSMISSION_CONFLICT,
                gap_bytes=0,
                conflicting_byte_ranges=[
                    ByteRange(start=40, end=80, direction=StreamDirection.RESP, exact=True)
                ],
                evidence_state=EvidenceState.CONFLICTING,
            ),
            Flow(
                uid="CTls13",
                orig=FlowEndpoint(host="198.51.100.13", port=40103),
                resp=FlowEndpoint(host="192.0.2.13", port=465),
                proto="tcp",
                history="ShADadFf",
                conn_state="SF",
                missed_bytes=0,
                orig_bytes=1500,
                resp_bytes=2200,
                reconstruction_quality=ReconstructionQuality.COMPLETE,
                gap_bytes=0,
                evidence_state=EvidenceState.OBSERVED,
            ),
        ],
        sessions=[
            EmailSession(
                uid="CSmtp",
                protocol=MailProtocol.SMTP,
                port_hint=PortHint.SMTP,
                payload_evidence=PayloadEvidence.SMTP,
                evidence_state=EvidenceState.OBSERVED,
                identification_confidence=0.99,
                corroboration="zeek+tshark",
                events=[
                    ProtocolEvent(
                        direction=StreamDirection.RESP,
                        kind=SessionEventKind.REPLY,
                        command=None,
                        text=HOSTILE_BANNER,
                        frame_number=3,
                        source=EventSource.ZEEK,
                    )
                ],
                explicit_upgrade=ExplicitUpgrade(
                    state=UpgradeState.TLS_ESTABLISHED,
                    evidence_state=EvidenceState.OBSERVED,
                    evidence_frames=[4, 5, 6],
                    downgrade_consistent=False,
                ),
            ),
            EmailSession(
                uid="CTrunc",
                protocol=MailProtocol.SMTP,
                port_hint=PortHint.SMTP,
                payload_evidence=PayloadEvidence.SMTP,
                evidence_state=EvidenceState.INCOMPLETE,
                identification_confidence=0.6,
                events=[
                    ProtocolEvent(
                        direction=StreamDirection.ORIG,
                        kind=SessionEventKind.STARTTLS,
                        command="STARTTLS",
                        frame_number=4,
                        source=EventSource.ZEEK,
                    )
                ],
                explicit_upgrade=ExplicitUpgrade(
                    state=UpgradeState.PLAINTEXT_FALLBACK,
                    evidence_state=EvidenceState.INCOMPLETE,
                    evidence_frames=[4],
                    downgrade_consistent=True,
                ),
            ),
            EmailSession(
                uid="CConf",
                protocol=MailProtocol.IMAP,
                port_hint=PortHint.IMAP,
                payload_evidence=PayloadEvidence.IMAP,
                evidence_state=EvidenceState.OBSERVED,
                implicit_tls=ImplicitTls(
                    correlated_protocol=MailProtocol.IMAP,
                    evidence_state=EvidenceState.OBSERVED,
                    source="alpn",
                    evidence_frames=[2],
                ),
            ),
            EmailSession(
                uid="CTls13",
                protocol=MailProtocol.SMTP,
                port_hint=PortHint.SMTP,
                payload_evidence=PayloadEvidence.SMTP,
                evidence_state=EvidenceState.OBSERVED,
                implicit_tls=ImplicitTls(
                    correlated_protocol=MailProtocol.SMTP,
                    evidence_state=EvidenceState.OBSERVED,
                    source="alpn",
                    evidence_frames=[2],
                ),
            ),
        ],
        handshakes=[
            TlsHandshake(
                uid="CSmtp",
                ssl_history="CsxX",
                established=True,
                resumed=False,
                hello_retry_request=False,
                visibility=HandshakeVisibility.FULL,
                version=TlsVersionEvidence(
                    selected="TLSv12",
                    source=VersionSource.LEGACY_RECORD,
                    evidence_state=EvidenceState.OBSERVED,
                    legacy_record_version="TLSv12",
                    client_supported_versions=["TLSv12"],
                ),
                cipher_suite=CipherSuiteEvidence(
                    name="TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                    code="0xc013",
                    evidence_state=EvidenceState.OBSERVED,
                ),
                key_exchange=KeyExchangeEvidence(
                    mechanism="ECDHE",
                    evidence_state=EvidenceState.OBSERVED,
                    source_fields=["cipher_suite", "server_key_exchange"],
                    selected_group="secp256r1",
                    selected_group_code=23,
                ),
                messages=[
                    HandshakeMessage(
                        kind=HandshakeMessageKind.CLIENT_HELLO,
                        direction=StreamDirection.ORIG,
                        history_letter="C",
                        frame_number=6,
                        evidence_state=EvidenceState.OBSERVED,
                    ),
                    HandshakeMessage(
                        kind=HandshakeMessageKind.SERVER_HELLO,
                        direction=StreamDirection.RESP,
                        history_letter="s",
                        frame_number=7,
                        evidence_state=EvidenceState.OBSERVED,
                    ),
                    HandshakeMessage(
                        kind=HandshakeMessageKind.CERTIFICATE,
                        direction=StreamDirection.RESP,
                        history_letter="x",
                        frame_number=8,
                        evidence_state=EvidenceState.OBSERVED,
                    ),
                    HandshakeMessage(
                        kind=HandshakeMessageKind.CERTIFICATE,
                        direction=StreamDirection.ORIG,
                        history_letter="X",
                        frame_number=9,
                        evidence_state=EvidenceState.INFERRED,
                    ),
                ],
                server_certificate_state=EvidenceState.OBSERVED,
                certificate_verify_state=EvidenceState.NOT_OBSERVABLE,
                certificate_verify_signature=HandshakeSignatureEvidence(
                    evidence_state=EvidenceState.NOT_OBSERVABLE
                ),
                evidence_state=EvidenceState.OBSERVED,
            ),
            TlsHandshake(
                uid="CTrunc",
                ssl_history="C",
                established=False,
                resumed=False,
                hello_retry_request=False,
                visibility=HandshakeVisibility.PARTIAL,
                version=TlsVersionEvidence(
                    selected="TLSv10",
                    source=VersionSource.LEGACY_RECORD,
                    evidence_state=EvidenceState.VERIFIED,
                    legacy_record_version="TLSv10",
                ),
                cipher_suite=CipherSuiteEvidence(evidence_state=EvidenceState.INCOMPLETE),
                key_exchange=KeyExchangeEvidence(evidence_state=EvidenceState.INCOMPLETE),
                messages=[
                    HandshakeMessage(
                        kind=HandshakeMessageKind.CLIENT_HELLO,
                        direction=StreamDirection.ORIG,
                        history_letter="C",
                        frame_number=6,
                        evidence_state=EvidenceState.INCOMPLETE,
                    )
                ],
                server_certificate_state=EvidenceState.INCOMPLETE,
                certificate_verify_state=EvidenceState.NOT_OBSERVABLE,
                certificate_verify_signature=HandshakeSignatureEvidence(
                    evidence_state=EvidenceState.NOT_OBSERVABLE
                ),
                evidence_state=EvidenceState.INCOMPLETE,
            ),
            TlsHandshake(
                uid="CTls13",
                ssl_history="CsiI",
                established=True,
                resumed=False,
                hello_retry_request=False,
                visibility=HandshakeVisibility.PARTIAL,
                version=TlsVersionEvidence(
                    selected="TLSv13",
                    source=VersionSource.SUPPORTED_VERSIONS,
                    evidence_state=EvidenceState.OBSERVED,
                    legacy_record_version="TLSv12",
                    server_supported_version="TLSv13",
                    client_supported_versions=["TLSv13"],
                ),
                cipher_suite=CipherSuiteEvidence(
                    name="TLS_AES_256_GCM_SHA384",
                    code="0x1302",
                    evidence_state=EvidenceState.OBSERVED,
                ),
                key_exchange=KeyExchangeEvidence(
                    mechanism="PSK",
                    evidence_state=EvidenceState.INDETERMINATE,
                    source_fields=["psk_key_exchange_modes"],
                    psk_key_exchange_modes=["psk_ke"],
                ),
                messages=[
                    HandshakeMessage(
                        kind=HandshakeMessageKind.CLIENT_HELLO,
                        direction=StreamDirection.ORIG,
                        history_letter="C",
                        frame_number=4,
                        evidence_state=EvidenceState.OBSERVED,
                    ),
                    HandshakeMessage(
                        kind=HandshakeMessageKind.SERVER_HELLO,
                        direction=StreamDirection.RESP,
                        history_letter="s",
                        frame_number=6,
                        evidence_state=EvidenceState.OBSERVED,
                    ),
                ],
                server_certificate_state=EvidenceState.NOT_OBSERVABLE,
                certificate_verify_state=EvidenceState.NOT_OBSERVABLE,
                certificate_verify_signature=HandshakeSignatureEvidence(
                    evidence_state=EvidenceState.NOT_OBSERVABLE
                ),
                evidence_state=EvidenceState.OBSERVED,
            ),
        ],
        certificates=[
            CertificateEvidence(
                der_sha256="1" * 64,
                uid="CSmtp",
                chain_index=0,
                role=CertificateRole.SERVER,
                source_frames=[8],
                syntax_valid=True,
                subject="CN=mail.example",
                issuer="CN=SecureMail Lab Intermediate CA,O=SecureMail Lab",
                serial_number="11",
                not_before=datetime(2020, 1, 1, tzinfo=UTC),
                not_after=datetime(2021, 1, 1, tzinfo=UTC),
                valid_at_capture_time=False,
                valid_at_analysis_time=False,
                expires_within_warning_window=False,
                public_key_algorithm="RSA",
                public_key_size=2048,
                effective_strength_bits=112,
                signature_algorithm="sha256WithRSAEncryption",
                evidence_state=EvidenceState.OBSERVED,
                validation=CertificateValidation(
                    certificate_observed=True,
                    syntax_valid=True,
                    path_valid_at_capture_time=False,
                    path_valid_at_analysis_time=False,
                    path_invalid_reasons_at_capture_time=["expired"],
                    path_invalid_reasons_at_analysis_time=["expired"],
                    identity_match=True,
                    reference_identity="mail.example",
                    reference_identity_source=ReferenceIdentitySource.SNI,
                    revocation_status=RevocationStatus.UNKNOWN,
                    trust_profile_id="offline_v1",
                    trust_store_digest=TRUST,
                    indeterminate_reasons=["revocation_unknown"],
                ),
            ),
            CertificateEvidence(
                der_sha256="2" * 64,
                uid="CSmtp",
                chain_index=1,
                role=CertificateRole.SERVER,
                source_frames=[8],
                syntax_valid=True,
                subject="CN=SecureMail Lab Intermediate CA,O=SecureMail Lab",
                issuer="CN=SecureMail Lab Root CA,O=SecureMail Lab",
                serial_number="22",
                not_before=datetime(2020, 1, 1, tzinfo=UTC),
                not_after=datetime(2099, 1, 1, tzinfo=UTC),
                valid_at_capture_time=True,
                valid_at_analysis_time=True,
                public_key_algorithm="RSA",
                public_key_size=2048,
                effective_strength_bits=112,
                signature_algorithm="sha256WithRSAEncryption",
                evidence_state=EvidenceState.INFERRED,
            ),
        ],
        findings=findings,
        policy_checks=checks,
        posture=posture,
    )
    fonts = font_resources()
    manifest = ReportManifest(
        generated_at=WHEN,
        case_id="reports_golden",
        capture_id=None,
        analysis_run_id="golden-run",
        source_capture_sha256=CAPTURE,
        working_copy_sha256=None,
        working_copy_availability=Availability.UNAVAILABLE,
        source_records=[
            SourceRecord(
                kind=SourceRecordKind.CASE,
                identifier="reports_golden",
                availability=Availability.PRESENT,
            ),
            SourceRecord(
                kind=SourceRecordKind.CAPTURE,
                identifier=None,
                availability=Availability.NOT_APPLICABLE,
            ),
            SourceRecord(
                kind=SourceRecordKind.ANALYSIS_RUN,
                identifier="golden-run",
                availability=Availability.PRESENT,
            ),
        ],
        artifact_hashes=[
            ArtifactHash(name="capture.pcapng", sha256=CAPTURE, availability=Availability.PRESENT),
            ArtifactHash(
                name="working_copy",
                sha256=None,
                availability=Availability.UNAVAILABLE,
            ),
        ],
        renderer=RendererManifest(
            pdf_renderer_version=weasyprint_version(),
            template_sha256=template_sha256(),
            fonts=fonts,
        ),
        signature=SignatureMetadata(),
        posture_summary=PostureSummary(
            assessment_state=posture.assessment_state,
            risk_score=posture.risk_score,
            finding_count=len(posture.prioritized_findings),
            unknown_count=posture.coverage.overall.unknown_count,
            not_observable_count=posture.coverage.overall.not_observable_count,
        ),
        configuration_digest=CONFIG,
        analyzer_bundle_digest=BUNDLE,
        policy_profile=PolicyProfile.IETF_CURRENT.value,
        policy_pack_version=PACK,
        trust_store_digest=TRUST,
        os_container=None,
        os_container_availability=Availability.UNAVAILABLE,
        dependency_versions={"weasyprint": weasyprint_version(), "jinja2": "3.1.6"},
    )
    return CanonicalReport(
        manifest=manifest,
        evidence=evidence,
        limitations=CaptureLimitations(
            truncated_packets_present=True,
            incomplete_flow_count=1,
            conflicting_flow_count=1,
            not_observable_certificate_count=1,
            unknown_check_count=posture.coverage.overall.unknown_count,
            not_observable_check_count=posture.coverage.overall.not_observable_count,
            notes=[
                "Hand-assembled golden report for renderer tests. Not produced from a PCAP.",
                "Hostile banner injected into a decoded SMTP reply to prove HTML escaping.",
            ],
        ),
        advisory=AdvisorySection(),
        analyst_conclusions=AnalystSection(),
    )


def main() -> None:
    report = build_canonical_report()
    payload = report.model_dump(mode="json")
    HERE.mkdir(parents=True, exist_ok=True)
    (HERE / "golden_report.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    schema = canonical_report_json_schema()
    schema_path = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "securemail"
        / "domain"
        / "reports"
        / "canonical_report.schema.json"
    )
    schema_path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    digest = sha256_digest(canonicalize(payload))
    fonts = {font.filename: font.sha256 for font in report.manifest.renderer.fonts}
    provenance = {
        "source": "hand-assembled",
        "generator": "tests/fixtures/reports/assemble.py",
        "created_at": "2026-09-04T12:00:00Z",
        "report_schema_version": report.schema_version,
        "canonical_json_sha256": digest,
        "template_sha256": report.manifest.renderer.template_sha256,
        "weasyprint_version": report.manifest.renderer.pdf_renderer_version,
        "fonts": fonts,
        "finding_codes": sorted({item.code for item in report.evidence.findings}),
        "pdf_page_count_min": 8,
        "pdf_page_count_max": 14,
        "notes": [
            "Golden report is the schema-first fixture for Step 9. HTML/PDF are rendered from it.",
            "PDF bytes are not goldened; tests extract text and assert a page-count range.",
        ],
    }
    (HERE / "provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(digest)


if __name__ == "__main__":
    main()
