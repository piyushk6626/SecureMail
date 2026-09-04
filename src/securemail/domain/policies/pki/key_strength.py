"""Data-driven effective security strength. RSA and ECC are never compared by raw bits."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

# NIST SP 800-57 Part 1 comparable strengths. Size thresholds are inclusive floors.
RSA_MODULUS_STRENGTH: tuple[tuple[int, int], ...] = (
    (1024, 80),
    (2048, 112),
    (3072, 128),
    (4096, 152),
    (7680, 192),
    (15360, 256),
)

DSA_PARAMETER_STRENGTH: tuple[tuple[int, int], ...] = RSA_MODULUS_STRENGTH

ECC_SIZE_STRENGTH: tuple[tuple[int, int], ...] = (
    (160, 80),
    (224, 112),
    (256, 128),
    (384, 192),
    (521, 256),
)

CURVE_STRENGTH: Mapping[str, int] = {
    "secp192r1": 80,
    "prime192v1": 80,
    "secp224r1": 112,
    "secp256r1": 128,
    "prime256v1": 128,
    "p-256": 128,
    "secp384r1": 192,
    "p-384": 192,
    "secp521r1": 256,
    "p-521": 256,
    "secp256k1": 128,
    "sect163k1": 80,
    "sect233k1": 112,
    "sect283k1": 128,
    "brainpoolp256r1": 128,
    "brainpoolp384r1": 192,
    "brainpoolp512r1": 256,
    "x25519": 128,
    "ed25519": 128,
    "x448": 224,
    "ed448": 224,
}

ALGORITHM_FIXED_STRENGTH: Mapping[str, int] = {
    "ED25519": 128,
    "ED448": 224,
    "X25519": 128,
    "X448": 224,
}


def _floor_lookup(table: Sequence[tuple[int, int]], size: int) -> int | None:
    matched: int | None = None
    for threshold, strength in table:
        if size >= threshold:
            matched = strength
            continue
        break
    return matched


def effective_strength_bits(
    *,
    algorithm: str | None,
    size: int | None = None,
    curve: str | None = None,
) -> int | None:
    """Return comparable security strength in bits, or None when unmapped."""

    if algorithm is None:
        return None
    token = algorithm.strip().upper().replace("-", "")
    if token in ALGORITHM_FIXED_STRENGTH:
        return ALGORITHM_FIXED_STRENGTH[token]
    if curve is not None:
        curve_strength = CURVE_STRENGTH.get(curve.strip().lower())
        if curve_strength is not None:
            return curve_strength
    if size is None or size <= 0:
        return None
    if token in {"RSA", "RSASSA", "RSAPSS"}:
        return _floor_lookup(RSA_MODULUS_STRENGTH, size)
    if token in {"DSA"}:
        return _floor_lookup(DSA_PARAMETER_STRENGTH, size)
    if token in {"ECDSA", "ECDH", "EC"}:
        return _floor_lookup(ECC_SIZE_STRENGTH, size)
    return None
