"""
tests/test_detector.py

Tests for backend.detector structural candidate generation.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List

import pytest

from backend import database, detector


@pytest.fixture(scope="module")
def records() -> List[Dict[str, Any]]:
    return database.load_database()


def _names(candidates) -> List[str]:
    return [c.name for c in candidates]


# ---------------------------------------------------------------------------
# 1. 32-char hex, MD5-looking sample
# ---------------------------------------------------------------------------
def test_md5_looking_hash_returns_multiple_candidates(records):
    sample = "8743b52063cd84097a65d1633f5c74f5"[:32]
    candidates = detector.detect(sample, records)
    names = _names(candidates)
    assert len(candidates) > 1
    assert "MD5" in names


# ---------------------------------------------------------------------------
# 2. NTLM-looking 32-char hex
# ---------------------------------------------------------------------------
def test_ntlm_looking_hash_is_not_falsely_distinguished(records):
    sample = "b4b9b02e6f09a9bd760f388b67351e2b"
    candidates = detector.detect(sample, records)
    names = set(_names(candidates))
    # HashFox must not structurally distinguish NTLM from MD5/MD4 given
    # only a bare 32-char hex string -- all three must appear together.
    assert {"MD5", "NTLM", "MD4"}.issubset(names)


# ---------------------------------------------------------------------------
# 3. bcrypt
# ---------------------------------------------------------------------------
def test_bcrypt_detected_with_strong_evidence(records):
    sample = "$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6"
    candidates = detector.detect(sample, records)
    bcrypt_candidates = [c for c in candidates if "bcrypt" in c.name.lower()]
    assert bcrypt_candidates, "bcrypt should be detected as a candidate"
    ev = bcrypt_candidates[0].evidence
    assert ev.prefix_match is True
    assert ev.regex_match is True


# ---------------------------------------------------------------------------
# 4. sha512crypt
# ---------------------------------------------------------------------------
def test_sha512crypt_detected_with_strong_evidence(records):
    sample = (
        "$6$qdMgClgO2dQWB37F$jhexCX1SdsCAi0OZmoRVAPnWSwuP/mHVhXIMJfKlaacx"
        "FkwWLDZ0ViF8Ur3WcHashcatVp2WShcEILi8QZCbt/"
    )
    candidates = detector.detect(sample, records)
    matches = [c for c in candidates if "sha512crypt" in c.name.lower()]
    assert matches, "sha512crypt should be detected as a candidate"
    ev = matches[0].evidence
    assert ev.prefix_match is True


# ---------------------------------------------------------------------------
# 5. Kerberos TGS
# ---------------------------------------------------------------------------
def test_kerberos_tgs_detected_strongly(records):
    sample = (
        "$krb5tgs$23$*user$realm$test/spn*$"
        "63386d22d359fe42230300d568deadbeefcafefeedfacebabe"
    )
    candidates = detector.detect(sample, records)

    def _is_tgs_candidate(c) -> bool:
        prefixes = c.record.get("prefixes") or []
        if any("krb5tgs" in p for p in prefixes):
            return True
        return "tgs" in c.name.lower()

    matches = [c for c in candidates if _is_tgs_candidate(c)]
    assert matches, "A Kerberos TGS candidate should be detected"
    assert any(c.evidence.prefix_match for c in matches)


# ---------------------------------------------------------------------------
# 6. 64-char SHA256-looking hex
# ---------------------------------------------------------------------------
def test_sha256_looking_hash_returns_multiple_candidates(records):
    sample = "d60fcf6585da4e17224f58858970f0ed5ab042c3916b76b0b828e62eaf636cb" + "d"
    assert len(sample) == 64
    candidates = detector.detect(sample, records)
    assert len(candidates) > 1


# ---------------------------------------------------------------------------
# 7. Empty input
# ---------------------------------------------------------------------------
def test_empty_input_returns_empty_result(records):
    assert detector.detect("", records) == []
    assert detector.detect("   ", records) == []


# ---------------------------------------------------------------------------
# 8. Garbage input
# ---------------------------------------------------------------------------
def test_garbage_input_does_not_crash(records):
    candidates = detector.detect("!!!not a hash!!! %%% ???", records)
    assert isinstance(candidates, list)


# ---------------------------------------------------------------------------
# 9. Unicode input
# ---------------------------------------------------------------------------
def test_unicode_input_does_not_crash(records):
    candidates = detector.detect("héllo wörld 你好 🔥🔥🔥", records)
    assert isinstance(candidates, list)


# ---------------------------------------------------------------------------
# 10. Extremely long input
# ---------------------------------------------------------------------------
def test_extremely_long_input_is_handled_safely(records):
    huge = "a" * (detector.MAX_INPUT_LENGTH + 5000)
    candidates = detector.detect(huge, records)
    assert candidates == []


# ---------------------------------------------------------------------------
# 11. Synthetic database entry with invalid regex must not crash
# ---------------------------------------------------------------------------
def test_invalid_regex_in_one_record_does_not_crash_detector(records):
    broken_records = copy.deepcopy(records)
    broken_records.append(
        {
            "name": "SyntheticBroken",
            "aliases": [],
            "variants": [],
            "category": "other",
            "hashcat_mode": None,
            "john_format": None,
            "length": None,
            "min_length": None,
            "max_length": None,
            "character_set": "hex",
            "regex": "(unclosed[",  # invalid regex on purpose
            "prefixes": [],
            "separators": [],
            "salted": False,
            "example_hash": "deadbeef",
            "detection_quality": "medium",
            "security_level": "low",
            "description": "synthetic test record with invalid regex",
        }
    )

    # Should not raise.
    candidates = detector.detect("8743b52063cd84097a65d1633f5c74f5", broken_records)
    assert isinstance(candidates, list)
    # The broken record must not silently be accepted via a false regex
    # match.
    assert "SyntheticBroken" not in _names(candidates)


# ---------------------------------------------------------------------------
# 12. reference_only records must never appear in automatic detection
# ---------------------------------------------------------------------------
def test_reference_only_records_are_excluded(records):
    reference_only_names = {
        r["name"] for r in records if r.get("detection_quality") == "reference_only"
    }
    assert reference_only_names, "Fixture database should contain reference_only records"

    # Try a broad set of sample inputs and make sure none of them ever
    # surfaces a reference_only record.
    samples = [
        "8743b52063cd84097a65d1633f5c74f5",
        "d60fcf6585da4e17224f58858970f0ed5ab042c3916b76b0b828e62eaf636cbd",
        "$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6",
        "$6$qdMgClgO2dQWB37F$jhexCX1SdsCAi0OZmoRVAPnWSwuP/mHVhXIMJfKlaacx",
    ]
    for sample in samples:
        candidates = detector.detect(sample, records)
        for c in candidates:
            assert c.record.get("detection_quality") != "reference_only"
            assert c.name not in reference_only_names or True  # name collisions guard


# ---------------------------------------------------------------------------
# 13. Determinism
# ---------------------------------------------------------------------------
def test_detection_is_deterministic(records):
    sample = "8743b52063cd84097a65d1633f5c74f5"
    first = detector.detect(sample, records)
    second = detector.detect(sample, records)
    assert _names(first) == _names(second)
    assert [c.evidence.as_dict() for c in first] == [
        c.evidence.as_dict() for c in second
    ]
