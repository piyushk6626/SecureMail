"""PKI policy functions: key strength, path validation, and identity matching."""

from securemail.domain.policies.pki.chain_validation import (
    ChainValidationInput,
    ChainValidationResult,
    PathReasonCode,
    TrustStoreSnapshot,
    build_trust_snapshot,
    validate_certificate_path,
)
from securemail.domain.policies.pki.identity import (
    IdentityMatchResult,
    IdentityReasonCode,
    SanEntry,
    extract_san_entries,
    match_service_identity,
)
from securemail.domain.policies.pki.key_strength import effective_strength_bits

__all__ = [
    "ChainValidationInput",
    "ChainValidationResult",
    "IdentityMatchResult",
    "IdentityReasonCode",
    "PathReasonCode",
    "SanEntry",
    "TrustStoreSnapshot",
    "build_trust_snapshot",
    "effective_strength_bits",
    "extract_san_entries",
    "match_service_identity",
    "validate_certificate_path",
]
