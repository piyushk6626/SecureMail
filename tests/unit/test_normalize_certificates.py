"""Certificate normalizer links extracted DER to ssl.log without fabricating TLS 1.3 certs."""

from datetime import UTC, datetime, timedelta
from hashlib import sha1, sha256

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from securemail.application.normalize_certificates import normalize_certificates
from securemail.application.normalize_handshakes import normalize_handshakes
from securemail.domain.evidence.flow import Flow, ReconstructionQuality
from securemail.domain.evidence.run import EvidenceState
from securemail.domain.policies.tls.key_exchange import TlsParameterIndex
from securemail.ports.analyzers import ExtractedCertificate


def _index() -> TlsParameterIndex:
    return TlsParameterIndex(
        digest="a" * 64,
        cipher_name_to_code={"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "0xC02F"},
        cipher_code_to_name={"0xC02F": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
        group_code_to_name={29: "x25519"},
        group_name_to_code={"x25519": 29},
    )


def _flow(uid: str = "Ctls") -> Flow:
    return Flow(
        uid=uid,
        orig={"host": "192.0.2.10", "port": 49152},
        resp={"host": "192.0.2.25", "port": 4433},
        proto="tcp",
        history="ShADad",
        conn_state="S1",
        missed_bytes=0,
        orig_bytes=200,
        resp_bytes=200,
        reconstruction_quality=ReconstructionQuality.COMPLETE,
        gap_bytes=0,
        gap_bytes_exact=True,
        evidence_state=EvidenceState.OBSERVED,
    )


def _der() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "securemail.test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2099, 1, 1, tzinfo=UTC))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


class _Store:
    def __init__(self) -> None:
        self.items: dict[str, bytes] = {}

    def put(self, payload: bytes) -> str:
        digest = sha256(payload).hexdigest()
        self.items[digest] = payload
        return digest

    def get(self, digest: str) -> bytes:
        return self.items[digest]


def test_tls12_certificate_is_parsed_from_extracted_der() -> None:
    payload = _der()
    extracted = ExtractedCertificate(sha256=sha256(payload).hexdigest(), fuid="F1", payload=payload)
    logs = {
        "ssl.log": [
            {
                "uid": "Ctls",
                "ts": datetime(2024, 1, 1, tzinfo=UTC).timestamp(),
                "ssl_history": "CsxknGIti",
                "established": True,
                "version": "TLSv12",
                "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "cert_chain_fps": [sha1(payload, usedforsecurity=False).hexdigest()],
            }
        ]
    }
    handshakes = normalize_handshakes(logs, [_flow()], _index())
    certs = normalize_certificates(
        logs,
        [extracted],
        handshakes,
        analysis_time=datetime(2026, 9, 4, tzinfo=UTC),
        expiry_warning=timedelta(days=30),
        artifact_store=_Store(),
    )
    assert len(certs) == 1
    assert certs[0].syntax_valid is True
    assert certs[0].public_key_algorithm == "RSA"
    assert certs[0].effective_strength_bits == 112
    assert certs[0].valid_at_capture_time is True
    assert certs[0].valid_at_analysis_time is True
    assert certs[0].signature_algorithm == "sha256WithRSAEncryption"
    assert certs[0].validation is None
    assert handshakes[0].certificate_verify_signature.evidence_state is EvidenceState.NOT_OBSERVABLE
    assert (
        handshakes[0].certificate_verify_signature.algorithm != certs[0].signature_algorithm
        or handshakes[0].certificate_verify_signature.algorithm is None
    )


def test_tls13_without_certificate_history_is_not_fabricated() -> None:
    payload = _der()
    extracted = ExtractedCertificate(sha256=sha256(payload).hexdigest(), payload=payload)
    logs = {
        "ssl.log": [
            {
                "uid": "Ctls",
                "ssl_history": "Cs",
                "established": True,
                "version": "TLSv13",
                "server_supported_version": 772,
                "cipher": "TLS_AES_128_GCM_SHA256",
            }
        ],
        "x509.log": [{"id": "F1", "certificate.subject": "CN=forged.example"}],
    }
    handshakes = normalize_handshakes(logs, [_flow()], _index())
    certs = normalize_certificates(
        logs,
        [extracted],
        handshakes,
        analysis_time=datetime(2026, 9, 4, tzinfo=UTC),
        expiry_warning=timedelta(days=30),
        artifact_store=_Store(),
    )
    assert certs == []
    assert handshakes[0].server_certificate_state is EvidenceState.NOT_OBSERVABLE


def test_server_leaf_gets_independent_path_and_identity_fields() -> None:
    from securemail.adapters.pki.trust_store import load_trust_store_snapshot
    from securemail.domain.evidence.certificate import RevocationStatus

    payload = _der()
    extracted = ExtractedCertificate(sha256=sha256(payload).hexdigest(), fuid="F1", payload=payload)
    logs = {
        "ssl.log": [
            {
                "uid": "Ctls",
                "ts": datetime(2024, 1, 1, tzinfo=UTC).timestamp(),
                "ssl_history": "CsxknGIti",
                "established": True,
                "version": "TLSv12",
                "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "cert_chain_fps": [sha1(payload, usedforsecurity=False).hexdigest()],
                "server_name": "securemail.test",
            }
        ]
    }
    snapshot = load_trust_store_snapshot()
    certs = normalize_certificates(
        logs,
        [extracted],
        normalize_handshakes(logs, [_flow()], _index()),
        analysis_time=datetime(2026, 9, 4, tzinfo=UTC),
        expiry_warning=timedelta(days=30),
        artifact_store=_Store(),
        trust_snapshot=snapshot,
        expected_hostname="wrong.example.test",
    )
    assert len(certs) == 1
    validation = certs[0].validation
    assert validation is not None
    assert validation.certificate_observed is True
    assert validation.path_valid_at_capture_time is False
    assert validation.path_invalid_reasons_at_capture_time
    assert validation.identity_match is False
    assert validation.reference_identity == "wrong.example.test"
    assert validation.reference_identity_source.value == "configured"
    assert validation.revocation_status is RevocationStatus.UNKNOWN
    assert validation.trust_store_digest == snapshot.digest
