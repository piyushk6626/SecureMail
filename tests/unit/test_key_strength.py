"""Effective security-strength table: RSA and ECC are not compared by raw bits."""

from securemail.domain.policies.pki.key_strength import effective_strength_bits


def test_rsa2048_is_112_bit_and_p256_is_128_bit() -> None:
    rsa = effective_strength_bits(algorithm="RSA", size=2048)
    ecdsa = effective_strength_bits(algorithm="ECDSA", size=256, curve="secp256r1")
    assert rsa == 112
    assert ecdsa == 128
    assert rsa != 2048
    assert ecdsa != 256
    assert rsa != ecdsa


def test_rsa1024_maps_to_80_bits() -> None:
    assert effective_strength_bits(algorithm="RSA", size=1024) == 80


def test_unmapped_algorithm_is_none() -> None:
    assert effective_strength_bits(algorithm="UNKNOWN", size=2048) is None
    assert effective_strength_bits(algorithm=None, size=2048) is None
