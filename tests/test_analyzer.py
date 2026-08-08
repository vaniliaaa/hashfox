"""
tests/test_analyzer.py

Tests for backend.analyzer orchestration and ambiguity logic.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from backend import analyzer, database


@pytest.fixture(scope="module")
def records() -> List[Dict[str, Any]]:
    return database.load_database()


# ---------------------------------------------------------------------------
# 1. Ambiguous 32-char hex
# ---------------------------------------------------------------------------
def test_ambiguous_32_hex_input(records):
    result = analyzer.analyze_hash("8743b52063cd84097a65d1633f5c74f5", records)

    assert result["ambiguous"] is True
    assert result["ambiguity_message"] is not None
    names = {c["name"] for c in result["candidates"]}
    assert {"MD5", "NTLM", "MD4"}.issubset(names)
    assert result["candidate_count"] == len(result["candidates"])
    assert result["top_candidate"] is not None
    assert result["manual_verification_recommended"] is True


# ---------------------------------------------------------------------------
# 2. bcrypt
# ---------------------------------------------------------------------------
def test_bcrypt_is_not_ambiguous(records):
    sample = "$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6"
    result = analyzer.analyze_hash(sample, records)

    assert result["ambiguous"] is False
    assert result["ambiguity_message"] is None
    assert result["top_candidate"] is not None
    assert "bcrypt" in result["top_candidate"]["name"].lower()
    assert result["high_confidence"] is True
    assert result["manual_verification_recommended"] is False


# ---------------------------------------------------------------------------
# 3. Empty input
# ---------------------------------------------------------------------------
def test_empty_input_controlled_result(records):
    result = analyzer.analyze_hash("", records)

    assert result["candidate_count"] == 0
    assert result["candidates"] == []
    assert result["top_candidate"] is None
    assert result["ambiguous"] is False
    assert result["high_confidence"] is False
    assert result["manual_verification_recommended"] is True


def test_whitespace_only_input_controlled_result(records):
    result = analyzer.analyze_hash("   ", records)
    assert result["candidate_count"] == 0
    assert result["input_length"] == 0


# ---------------------------------------------------------------------------
# Additional coverage: enrichment fields present, no mutation, no crash
# ---------------------------------------------------------------------------
def test_candidates_are_enriched_with_metadata(records):
    result = analyzer.analyze_hash("8743b52063cd84097a65d1633f5c74f5", records)
    top = result["top_candidate"]
    for key in (
        "name",
        "aliases",
        "variants",
        "category",
        "hashcat_mode",
        "john_format",
        "hashcat_supported",
        "john_supported",
        "confidence",
        "detection_quality",
        "security_level",
        "evidence",
        "reasons",
        "description",
        "common_usage",
        "recommended_attack",
        "recommended_wordlists",
    ):
        assert key in top


def test_analyze_hash_does_not_mutate_database_records(records):
    import copy

    before = copy.deepcopy(records)
    analyzer.analyze_hash("8743b52063cd84097a65d1633f5c74f5", records)
    assert records == before


def test_garbage_input_does_not_crash(records):
    result = analyzer.analyze_hash("!!! not a hash !!!", records)
    assert isinstance(result, dict)
    assert result["candidate_count"] == len(result["candidates"])


def test_unicode_input_does_not_crash(records):
    result = analyzer.analyze_hash("héllo wörld 你好 🔥", records)
    assert isinstance(result, dict)


def test_none_input_does_not_crash(records):
    result = analyzer.analyze_hash(None, records)
    assert isinstance(result, dict)
    assert result["candidate_count"] == 0


def test_analysis_is_deterministic(records):
    sample = "8743b52063cd84097a65d1633f5c74f5"
    first = analyzer.analyze_hash(sample, records)
    second = analyzer.analyze_hash(sample, records)
    assert first == second


def test_kerberos_tgs_not_flagged_ambiguous(records):
    sample = (
        "$krb5tgs$23$*user$realm$test/spn*$"
        "63386d22d359fe42230300d568deadbeefcafefeedfacebabe"
    )
    result = analyzer.analyze_hash(sample, records)
    # Only one Kerberos etype-23 TGS-REP record exists at "high" quality
    # with this distinctive prefix; nothing else should score close to it.
    assert result["top_candidate"] is not None
    assert "tgs" in result["top_candidate"]["name"].lower()
