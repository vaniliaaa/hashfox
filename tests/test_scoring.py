"""
tests/test_scoring.py

Tests for backend.scoring confidence computation and ambiguity handling.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from backend import database, detector, scoring


@pytest.fixture(scope="module")
def records() -> List[Dict[str, Any]]:
    return database.load_database()


def run(sample: str, records) -> List[Dict[str, Any]]:
    candidates = detector.detect(sample, records)
    return scoring.score_candidates(candidates)


# ---------------------------------------------------------------------------
# Ambiguous 32-char hex: MD5 / NTLM / MD4 must not have one declared a
# false winner with near-certain confidence.
# ---------------------------------------------------------------------------
def test_ambiguous_32_char_hex_does_not_overclaim(records):
    sample = "8743b52063cd84097a65d1633f5c74f5"
    results = run(sample, records)
    names = {r["name"] for r in results}
    assert {"MD5", "NTLM", "MD4"}.issubset(names)

    by_name = {r["name"]: r for r in results}
    md5_conf = by_name["MD5"]["confidence"]
    ntlm_conf = by_name["NTLM"]["confidence"]
    md4_conf = by_name["MD4"]["confidence"]

    # None of the structurally-indistinguishable candidates may claim
    # nearly-certain confidence.
    assert md5_conf <= scoring.AMBIGUOUS_GROUP_CAP
    assert ntlm_conf <= scoring.AMBIGUOUS_GROUP_CAP
    assert md4_conf <= scoring.AMBIGUOUS_GROUP_CAP

    # Structurally indistinguishable candidates must be equalized.
    assert md5_conf == ntlm_conf == md4_conf


def test_ambiguous_64_char_hex_returns_multiple_capped_candidates(records):
    sample = "d60fcf6585da4e17224f58858970f0ed5ab042c3916b76b0b828e62eaf636cbd"
    results = run(sample, records)
    assert len(results) > 1
    for r in results:
        assert r["confidence"] <= scoring.AMBIGUOUS_GROUP_CAP


# ---------------------------------------------------------------------------
# Distinctive formats should score highly.
# ---------------------------------------------------------------------------
def test_bcrypt_scores_highly(records):
    sample = "$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6"
    results = run(sample, records)
    bcrypt_results = [r for r in results if "bcrypt" in r["name"].lower()]
    assert bcrypt_results
    assert bcrypt_results[0]["confidence"] >= 80


def test_sha512crypt_scores_highly(records):
    sample = (
        "$6$qdMgClgO2dQWB37F$jhexCX1SdsCAi0OZmoRVAPnWSwuP/mHVhXIMJfKlaacx"
        "FkwWLDZ0ViF8Ur3WcHashcatVp2WShcEILi8QZCbt/"
    )
    results = run(sample, records)
    matches = [r for r in results if "sha512crypt" in r["name"].lower()]
    assert matches
    assert matches[0]["confidence"] >= 70


def test_kerberos_tgs_scores_highly(records):
    sample = (
        "$krb5tgs$23$*user$realm$test/spn*$"
        "63386d22d359fe42230300d568deadbeefcafefeedfacebabe"
    )
    results = run(sample, records)
    matches = [r for r in results if "tgs" in r["name"].lower()]
    assert matches
    # This database record only carries a distinctive prefix (no regex
    # or length data for this particular Kerberos entry), so scoring
    # is necessarily a bit lower than formats with prefix+regex+length
    # agreement (e.g. bcrypt, sha512crypt) -- but a unique, highly
    # distinctive prefix like `$krb5tgs$` should still clearly stand
    # out above the ambiguous-group cap used for generic hex blobs.
    assert matches[0]["confidence"] >= 50


# ---------------------------------------------------------------------------
# Output shape / reasons
# ---------------------------------------------------------------------------
def test_result_shape_contains_expected_fields(records):
    sample = "$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6"
    results = run(sample, records)
    assert results
    top = results[0]
    for key in (
        "name",
        "aliases",
        "variants",
        "hashcat_mode",
        "john_format",
        "category",
        "security_level",
        "confidence",
        "detection_quality",
        "evidence",
        "reasons",
    ):
        assert key in top
    assert isinstance(top["reasons"], list)
    assert len(top["reasons"]) > 0


def test_empty_candidates_returns_empty_results():
    assert scoring.score_candidates([]) == []


# ---------------------------------------------------------------------------
# Deterministic ordering
# ---------------------------------------------------------------------------
def test_scoring_is_deterministic(records):
    sample = "8743b52063cd84097a65d1633f5c74f5"
    first = run(sample, records)
    second = run(sample, records)
    assert first == second


def test_results_sorted_by_confidence_descending(records):
    sample = "8743b52063cd84097a65d1633f5c74f5"
    results = run(sample, records)
    confidences = [r["confidence"] for r in results]
    assert confidences == sorted(confidences, reverse=True)


def test_no_result_ever_reaches_absolute_certainty(records):
    samples = [
        "8743b52063cd84097a65d1633f5c74f5",
        "$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6",
        "$6$qdMgClgO2dQWB37F$jhexCX1SdsCAi0OZmoRVAPnWSwuP/mHVhXIMJfKlaacx",
    ]
    for sample in samples:
        for r in run(sample, records):
            assert r["confidence"] <= scoring.MAX_CONFIDENCE
            assert r["confidence"] < 100
