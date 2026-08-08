"""
backend/analyzer.py

Orchestration layer for HashFox.

This module is intentionally "thin": it does not implement any
structural detection or scoring logic itself. It loads the offline
database (backend/database.py), runs the existing detector/scoring
pipeline (backend/detector.py, backend/scoring.py), enriches the
ranked results with additional database metadata, and produces a
single clean structured result suitable for a future CLI, API, or
frontend layer to consume.

No network access. No hashing. No cracking.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from backend import database, detector, scoring

# ---------------------------------------------------------------------------
# Ambiguity policy
# ---------------------------------------------------------------------------
# Two or more top-ranked candidates are considered "ambiguous" when their
# confidence scores are within this many points of each other. This
# mirrors (and stays consistent with) the ambiguous-group equalization
# already performed in backend/scoring.py, but is re-derived here from
# the final ranked confidence values so analyzer.py does not need to
# reach into scoring internals.
AMBIGUITY_CONFIDENCE_DELTA = 5

# A result is considered "high confidence" only when there is a single
# clear top candidate (not ambiguous) and its confidence meets this
# floor.
HIGH_CONFIDENCE_THRESHOLD = 85

DEFAULT_AMBIGUITY_MESSAGE = (
    "Multiple formats share the same structural signature. Verify the "
    "source/context before selecting a cracking mode."
)


def _enrich_candidate(result: Dict[str, Any], record_by_name: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Attach additional read-only database metadata to a scored result.

    Args:
        result: One scored candidate dict as produced by
            backend.scoring.score_candidates.
        record_by_name: Lookup of original database records by name,
            used only to pull additional descriptive fields. Never
            mutated, and mutation of the source records is avoided by
            only reading from them here.

    Returns:
        Dict[str, Any]: A new dict; the original `result` is not mutated.
    """
    enriched = dict(result)
    record = record_by_name.get(result.get("name"), {})

    enriched["hashcat_supported"] = record.get("hashcat_supported", None)
    enriched["john_supported"] = record.get("john_supported", None)
    enriched["description"] = record.get("description")
    enriched["common_usage"] = list(record.get("common_usage") or [])
    enriched["recommended_attack"] = list(record.get("recommended_attack") or [])
    enriched["recommended_wordlists"] = list(record.get("recommended_wordlists") or [])
    enriched["salted"] = record.get("salted", None)

    return enriched


def _determine_ambiguity(candidates: List[Dict[str, Any]]) -> tuple:
    """Deterministically decide whether the result set is ambiguous.

    Args:
        candidates: Ranked, scored candidate dicts (already sorted by
            confidence descending, per backend.scoring).

    Returns:
        (ambiguous: bool, ambiguity_message: Optional[str])
    """
    if len(candidates) < 2:
        return False, None

    top_confidence = candidates[0]["confidence"]
    close_candidates = [
        c for c in candidates
        if (top_confidence - c["confidence"]) <= AMBIGUITY_CONFIDENCE_DELTA
    ]

    if len(close_candidates) > 1:
        return True, DEFAULT_AMBIGUITY_MESSAGE

    return False, None


def analyze_hash(value: str, records: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Run the full detection + scoring pipeline and return a structured result.

    Args:
        value: The raw unknown hash / encoded credential string.
        records: Optional pre-loaded database records (mainly for
            testing). When omitted, the database is loaded via
            backend.database.load_database().

    Returns:
        Dict[str, Any]: Structured analysis result. Never raises for
        malformed/empty/garbage input; instead returns a controlled
        result describing the (possibly empty) outcome.
    """
    if records is None:
        records = database.load_database()

    record_by_name: Dict[str, Dict[str, Any]] = {}
    for r in records:
        if isinstance(r, dict) and "name" in r:
            # First occurrence wins; database is assumed to have unique
            # names, but we never let a later duplicate silently
            # overwrite metadata used for enrichment.
            record_by_name.setdefault(r["name"], r)

    raw_value = value if value is not None else ""
    normalized = detector.normalize_input(raw_value)

    structural_candidates = detector.detect(raw_value, records)
    scored = scoring.score_candidates(structural_candidates)

    ranked_candidates = [_enrich_candidate(r, record_by_name) for r in scored]

    ambiguous, ambiguity_message = _determine_ambiguity(ranked_candidates)

    top_candidate = ranked_candidates[0] if ranked_candidates else None

    high_confidence = bool(
        top_candidate is not None
        and not ambiguous
        and top_candidate["confidence"] >= HIGH_CONFIDENCE_THRESHOLD
    )

    manual_verification_recommended = bool(
        top_candidate is None or ambiguous or not high_confidence
    )

    return {
        "original_input": raw_value,
        "input_length": len(normalized),
        "candidate_count": len(ranked_candidates),
        "candidates": ranked_candidates,
        "top_candidate": top_candidate,
        "ambiguous": ambiguous,
        "ambiguity_message": ambiguity_message,
        "high_confidence": high_confidence,
        "manual_verification_recommended": manual_verification_recommended,
    }
