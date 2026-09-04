"""RFC 8785 canonicalization is deterministic and pinned for the golden report."""

from __future__ import annotations

import copy
import json
import math

import pytest
from tests.support.fixture_harness import load_golden_report, repo_root

from securemail.adapters.reports.canonical_json import (
    CanonicalJsonError,
    canonicalize,
    sha256_digest,
)


def _provenance() -> dict[str, object]:
    path = repo_root() / "tests" / "fixtures" / "reports" / "provenance.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_rfc8785_object_key_order() -> None:
    # RFC 8785 §3.2.3: properties sorted by UTF-16 code units.
    assert canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_rfc8785_unicode_key_order() -> None:
    payload = {"\u20ac": "Euro Symbol", "1": "One"}
    assert canonicalize(payload) == '{"1":"One","€":"Euro Symbol"}'.encode()


def test_rfc8785_literals_and_integers() -> None:
    assert canonicalize({"literals": [None, True, False], "n": 0}) == (
        b'{"literals":[null,true,false],"n":0}'
    )


def test_repeated_canonicalize_is_byte_identical() -> None:
    payload = load_golden_report()
    first = canonicalize(payload)
    second = canonicalize(payload)
    assert first == second
    assert first == canonicalize(copy.deepcopy(payload))


def test_golden_hash_is_pinned() -> None:
    digest = sha256_digest(canonicalize(load_golden_report()))
    assert digest == _provenance()["canonical_json_sha256"]


def test_canonicalize_does_not_mutate_input() -> None:
    payload = load_golden_report()
    original = copy.deepcopy(payload)
    canonicalize(payload)
    assert payload == original


def test_non_finite_floats_are_rejected() -> None:
    with pytest.raises(CanonicalJsonError):
        canonicalize({"n": math.nan})
    with pytest.raises(CanonicalJsonError):
        canonicalize({"n": math.inf})
