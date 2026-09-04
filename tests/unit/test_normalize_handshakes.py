"""Handshake normalization: version precedence, history, frames, truncation."""

from securemail.application.normalize_handshakes import (
    decode_signature_scheme,
    decode_tls_version,
    messages_from_ssl_history,
    normalize_handshakes,
    resolve_selected_version,
)
from securemail.domain.evidence.flow import Flow, ReconstructionQuality, ReconstructionReasonCode
from securemail.domain.evidence.handshake import (
    HandshakeMessageKind,
    HandshakeVisibility,
    VersionSource,
)
from securemail.domain.evidence.run import EvidenceState
from securemail.domain.policies.tls.key_exchange import TlsParameterIndex


def _index() -> TlsParameterIndex:
    return TlsParameterIndex(
        digest="a" * 64,
        cipher_name_to_code={
            "TLS_AES_128_GCM_SHA256": "0x1301",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "0xC02F",
            "TLS_RSA_WITH_AES_128_CBC_SHA": "0x002F",
        },
        cipher_code_to_name={
            "0x1301": "TLS_AES_128_GCM_SHA256",
            "0xC02F": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "0x002F": "TLS_RSA_WITH_AES_128_CBC_SHA",
        },
        group_code_to_name={29: "x25519", 23: "secp256r1"},
        group_name_to_code={"x25519": 29, "secp256r1": 23},
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


def test_decode_tls_version_numeric_and_string() -> None:
    assert decode_tls_version(772) == "TLSv13"
    assert decode_tls_version(771) == "TLSv12"
    assert decode_tls_version("TLSv13") == "TLSv13"
    assert decode_tls_version("TLS 1.2") == "TLSv12"


def test_supported_versions_wins_over_legacy_record_version() -> None:
    version = resolve_selected_version(
        {
            "version": "TLSv12",
            "server_version": 769,
            "server_supported_version": 771,
            "client_supported_versions": [771, 769],
        },
        "Csxn",
    )
    assert version.selected == "TLSv12"
    assert version.source is VersionSource.SUPPORTED_VERSIONS
    assert version.legacy_record_version == "TLSv10"
    assert version.client_supported_versions == ["TLSv12", "TLSv10"]


def test_client_hello_offers_never_become_selected_version() -> None:
    version = resolve_selected_version(
        {
            "client_version": 771,
            "client_supported_versions": [772, 771],
            "version": "TLSv13",
        },
        "C",
    )
    assert version.selected is None
    assert version.source is None
    assert version.evidence_state is EvidenceState.INCOMPLETE
    assert version.client_supported_versions == ["TLSv13", "TLSv12"]


def test_ssl_history_reconstruction_is_case_sensitive() -> None:
    messages = messages_from_ssl_history("Csxkn")
    assert [message.history_letter for message in messages] == ["C", "s", "x", "k", "n"]
    assert [message.kind for message in messages] == [
        HandshakeMessageKind.CLIENT_HELLO,
        HandshakeMessageKind.SERVER_HELLO,
        HandshakeMessageKind.CERTIFICATE,
        HandshakeMessageKind.SERVER_KEY_EXCHANGE,
        HandshakeMessageKind.SERVER_HELLO_DONE,
    ]
    assert messages[0].direction.value == "orig"
    assert messages[1].direction.value == "resp"


def test_hello_retry_request_letter_and_tshark_frame() -> None:
    logs = {
        "ssl.log": [
            {
                "uid": "Ctls",
                "ssl_history": "CjCs",
                "established": True,
                "version": "TLSv13",
                "server_version": 771,
                "server_supported_version": 772,
                "cipher": "TLS_AES_128_GCM_SHA256",
                "server_key_share_group": 23,
                "client_key_share_groups": [29, 23],
            }
        ]
    }
    frames = [
        {
            "frame.number": "4",
            "ip.src": "192.0.2.10",
            "tcp.srcport": "49152",
            "ip.dst": "192.0.2.25",
            "tcp.dstport": "4433",
            "tls.handshake.type": "1",
        },
        {
            "frame.number": "5",
            "ip.src": "192.0.2.25",
            "tcp.srcport": "4433",
            "ip.dst": "192.0.2.10",
            "tcp.dstport": "49152",
            "tls.handshake.type": "2",
            "tls.handshake.extensions_key_share_selected_group": "23",
        },
        {
            "frame.number": "7",
            "ip.src": "192.0.2.10",
            "tcp.srcport": "49152",
            "ip.dst": "192.0.2.25",
            "tcp.dstport": "4433",
            "tls.handshake.type": "1",
        },
        {
            "frame.number": "8",
            "ip.src": "192.0.2.25",
            "tcp.srcport": "4433",
            "ip.dst": "192.0.2.10",
            "tcp.dstport": "49152",
            "tls.handshake.type": "2",
        },
    ]
    handshakes = normalize_handshakes(logs, [_flow()], _index(), tshark_frames=frames)
    assert len(handshakes) == 1
    handshake = handshakes[0]
    assert handshake.hello_retry_request is True
    assert handshake.version.selected == "TLSv13"
    assert handshake.version.source is VersionSource.SUPPORTED_VERSIONS
    assert handshake.cipher_suite.code == "0x1301"
    kinds = [message.kind for message in handshake.messages]
    assert HandshakeMessageKind.HELLO_RETRY_REQUEST in kinds
    hrr = next(
        message
        for message in handshake.messages
        if message.kind is HandshakeMessageKind.HELLO_RETRY_REQUEST
    )
    assert hrr.frame_number == 5
    assert hrr.evidence_state is EvidenceState.OBSERVED
    assert handshake.server_certificate_state is EvidenceState.NOT_OBSERVABLE
    assert handshake.certificate_verify_state is EvidenceState.NOT_OBSERVABLE
    assert handshake.visibility is HandshakeVisibility.PARTIAL


def test_truncated_client_hello_is_incomplete_not_a_guess() -> None:
    logs = {
        "ssl.log": [
            {
                "uid": "Ctls",
                "ssl_history": "C",
                "established": False,
                "client_supported_versions": [772, 771],
                "client_ciphers": [4865],
            }
        ]
    }
    flow = _flow()
    flow = flow.model_copy(
        update={
            "reconstruction_quality": ReconstructionQuality.INCOMPLETE,
            "reason_code": ReconstructionReasonCode.SNAPLEN_TRUNCATION,
            "evidence_state": EvidenceState.INCOMPLETE,
        }
    )
    handshakes = normalize_handshakes(logs, [flow], _index())
    assert len(handshakes) == 1
    handshake = handshakes[0]
    assert handshake.version.selected is None
    assert handshake.version.evidence_state is EvidenceState.INCOMPLETE
    assert handshake.evidence_state is EvidenceState.INCOMPLETE
    assert handshake.cipher_suite.name is None
    assert handshake.visibility is HandshakeVisibility.PARTIAL


def test_tls12_static_rsa_inferred_from_suite_grammar() -> None:
    logs = {
        "ssl.log": [
            {
                "uid": "Ctls",
                "ssl_history": "Csxn",
                "established": True,
                "version": "TLSv12",
                "server_version": 771,
                "cipher": "TLS_RSA_WITH_AES_128_CBC_SHA",
            }
        ]
    }
    handshake = normalize_handshakes(logs, [_flow()], _index())[0]
    assert handshake.cipher_suite.code == "0x002F"
    assert handshake.key_exchange.mechanism == "RSA"
    assert handshake.key_exchange.evidence_state is EvidenceState.INFERRED
    assert handshake.visibility is HandshakeVisibility.FULL
    assert handshake.server_certificate_state is EvidenceState.OBSERVED


def test_decode_signature_scheme_maps_iana_codes() -> None:
    assert decode_signature_scheme("0x0201") == "rsa_pkcs1_sha1"
    assert decode_signature_scheme(0x0804) == "rsa_pss_rsae_sha256"
    assert decode_signature_scheme("rsa_pkcs1_sha256") == "rsa_pkcs1_sha256"


def test_certificate_verify_algorithm_is_independent_of_x509() -> None:
    logs = {
        "ssl.log": [
            {
                "uid": "Ctls",
                "ssl_history": "Csxny",
                "established": True,
                "version": "TLSv12",
                "server_version": 771,
                "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            }
        ]
    }
    frames = [
        {
            "frame.number": "6",
            "ip.src": "192.0.2.25",
            "tcp.srcport": "4433",
            "ip.dst": "192.0.2.10",
            "tcp.dstport": "49152",
            "tls.handshake.type": "11,16,15",
            "tls.handshake.sig_hash_alg": "0x0201",
        }
    ]
    handshake = normalize_handshakes(logs, [_flow()], _index(), tshark_frames=frames)[0]
    assert handshake.certificate_verify_state is EvidenceState.OBSERVED
    assert handshake.certificate_verify_signature.algorithm == "rsa_pkcs1_sha1"
    assert handshake.certificate_verify_signature.evidence_state is EvidenceState.OBSERVED


def test_certificate_verify_without_frames_stays_incomplete() -> None:
    logs = {
        "ssl.log": [
            {
                "uid": "Ctls",
                "ssl_history": "Csxny",
                "established": True,
                "version": "TLSv12",
                "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            }
        ]
    }
    handshake = normalize_handshakes(logs, [_flow()], _index())[0]
    assert handshake.certificate_verify_signature.algorithm is None
    assert handshake.certificate_verify_signature.evidence_state is EvidenceState.INCOMPLETE
