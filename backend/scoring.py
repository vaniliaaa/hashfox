"""
backend/scoring.py

Deterministic, explainable, ambiguity-aware confidence scoring for
HashFox detection candidates.

Given the structural :class:`~backend.detector.Candidate` objects
produced by :mod:`backend.detector`, this module:

    1. Weights each piece of structural evidence individually.
    2. Applies a small prior derived from the database's own
       `detection_quality` label (never used as the entire score).
    3. Detects groups of candidates that are structurally
       indistinguishable given the available evidence, and caps /
       equalizes their confidence rather than arbitrarily picking a
       winner.
    4. Produces a deterministic, human-readable ranked result list.

This module never accesses the network and never mutates the input
database records.
"""

from __future__ import annotations

from typing import Any, Dict, List

from backend.detector import Candidate

# ---------------------------------------------------------------------------
# Evidence weighting
# ---------------------------------------------------------------------------
# These weights encode *relative* strength of evidence, as described in
# the project handoff:
#
#   distinctive prefix   -> very strong
#   verified regex       -> strong
#   exact length         -> moderate
#   length range         -> weaker than exact length
#   character set        -> supporting evidence only (never sufficient alone)
#   separator structure  -> potentially strong
#   detection_quality    -> prior only (small nudge, not the score itself)
#
# Weights are additive and then capped, so a format that matches on
# several independent axes (e.g. bcrypt: prefix + regex + length range)
# scores much higher than one that only matches on a single weak axis.

WEIGHT_PREFIX = 50
WEIGHT_REGEX = 40
WEIGHT_EXACT_LENGTH = 20
WEIGHT_LENGTH_RANGE = 12
WEIGHT_CHARSET = 8
WEIGHT_SEPARATOR = 18

PRIOR_BY_QUALITY = {
    "high": 5,
    "medium": 0,
    "low": -5,
}

# HashFox is an offline heuristic tool; it must never claim absolute
# certainty, even for very distinctive formats.
MAX_CONFIDENCE = 99
MIN_CONFIDENCE = 1

# When two or more candidates share identical structural evidence (i.e.
# nothing we measured can distinguish them), their confidence is
# equalized and capped at this value, no matter how high the raw
# evidence-based score would otherwise be.
AMBIGUOUS_GROUP_CAP = 85


def _raw_score(evidence_signature: tuple, detection_quality: str) -> int:
    """Compute the additive, evidence-based raw score for one candidate.

    Args:
        evidence_signature: Tuple of booleans in the order
            (regex_match, prefix_match, exact_length_match,
            length_range_match, charset_match, separator_match), as
            produced by ``Evidence.signature()``.
        detection_quality: The record's detection_quality label, used
            only as a small prior.

    Returns:
        int: Raw additive score, not yet clamped to [MIN, MAX].
    """
    (
        regex_match,
        prefix_match,
        exact_length_match,
        length_range_match,
        charset_match,
        separator_match,
    ) = evidence_signature

    score = 0
    if prefix_match:
        score += WEIGHT_PREFIX
    if regex_match:
        score += WEIGHT_REGEX
    if exact_length_match:
        score += WEIGHT_EXACT_LENGTH
    if length_range_match:
        score += WEIGHT_LENGTH_RANGE
    if charset_match:
        score += WEIGHT_CHARSET
    if separator_match:
        score += WEIGHT_SEPARATOR

    score += PRIOR_BY_QUALITY.get(detection_quality, 0)
    return score


def _specificity(evidence_signature: tuple) -> int:
    """A deterministic specificity measure used only for tie-breaking.

    Higher means the evidence collected is, in principle, more specific
    to this format (used to break ties between equal confidence scores
    that are NOT part of the same ambiguous group).
    """
    (
        regex_match,
        prefix_match,
        exact_length_match,
        length_range_match,
        charset_match,
        separator_match,
    ) = evidence_signature
    return (
        (2 if prefix_match else 0)
        + (2 if regex_match else 0)
        + (1 if exact_length_match else 0)
        + (1 if length_range_match else 0)
        + (1 if separator_match else 0)
        + (0 if charset_match else 0)  # supporting only, no specificity credit
    )


def _build_reasons(candidate: Candidate, ambiguous_group_size: int) -> List[str]:
    """Build a deterministic, human-readable explanation for a candidate."""
    reasons: List[str] = []
    ev = candidate.evidence

    if ev.prefix_match:
        reasons.append("Distinctive prefix matched.")
    if ev.regex_match:
        reasons.append("Verified structural regex pattern matched.")
    if ev.exact_length_match:
        reasons.append("Exact length matched.")
    if ev.length_range_match:
        reasons.append("Length fell within the format's expected range.")
    if ev.charset_match:
        reasons.append("Character set matched (supporting evidence only).")
    if ev.separator_match:
        reasons.append("Separator structure matched.")

    quality = candidate.record.get("detection_quality")
    if quality == "high":
        reasons.append("Database marks this format's detectability as high.")
    elif quality == "low":
        reasons.append(
            "Database marks this format's detectability as low; "
            "confidence was nudged down accordingly."
        )

    for note in candidate.notes:
        reasons.append(note)

    if ambiguous_group_size > 1:
        reasons.append(
            f"Confidence capped/reduced because {ambiguous_group_size} "
            "formats share structurally indistinguishable evidence in "
            "this analysis."
        )

    return reasons


def score_candidates(candidates: List[Candidate]) -> List[Dict[str, Any]]:
    """Score, ambiguity-adjust, and deterministically rank candidates.

    Args:
        candidates: Structural candidates from :func:`backend.detector.detect`.

    Returns:
        List[Dict[str, Any]]: Ranked candidate result dictionaries, each
        containing name/aliases/variants/hashcat_mode/john_format/
        category/security_level/confidence/detection_quality/evidence/
        reasons. Empty list if `candidates` is empty.
    """
    if not candidates:
        return []

    # Step 1: raw evidence-based score per candidate.
    raw_scores: Dict[int, int] = {}
    for idx, candidate in enumerate(candidates):
        quality = candidate.record.get("detection_quality", "")
        raw_scores[idx] = _raw_score(candidate.evidence.signature(), quality)

    # Step 2: group candidates that are structurally indistinguishable,
    # i.e. they share the exact same evidence signature. This is the
    # ambiguity-aware core of HashFox: we never let one format "win"
    # over others that matched on exactly the same signals.
    groups: Dict[tuple, List[int]] = {}
    for idx, candidate in enumerate(candidates):
        groups.setdefault(candidate.evidence.signature(), []).append(idx)

    final_scores: Dict[int, int] = {}
    group_size_by_idx: Dict[int, int] = {}

    for signature, idxs in groups.items():
        group_size_by_idx.update({i: len(idxs) for i in idxs})

        if len(idxs) == 1:
            final_scores[idxs[0]] = raw_scores[idxs[0]]
            continue

        # Equalize: structurally indistinguishable candidates must not
        # receive different confidence just because of unrelated
        # database metadata (e.g. one happens to have a "high" prior).
        # Use the average of their raw scores, then apply the ambiguity
        # cap. Rounding is deterministic (banker's rounding avoided by
        # using integer division with .5 rounding up).
        avg_score = sum(raw_scores[i] for i in idxs) / len(idxs)
        equalized = int(avg_score + 0.5)
        capped = min(equalized, AMBIGUOUS_GROUP_CAP)
        for i in idxs:
            final_scores[i] = capped

    # Step 3: clamp to the allowed confidence range.
    for idx in final_scores:
        final_scores[idx] = max(MIN_CONFIDENCE, min(MAX_CONFIDENCE, final_scores[idx]))

    # Step 4: build output records.
    results: List[Dict[str, Any]] = []
    for idx, candidate in enumerate(candidates):
        record = candidate.record
        confidence = final_scores[idx]
        group_size = group_size_by_idx.get(idx, 1)

        results.append(
            {
                "name": record.get("name"),
                "aliases": record.get("aliases", []) or [],
                "variants": record.get("variants", []) or [],
                "hashcat_mode": record.get("hashcat_mode"),
                "john_format": record.get("john_format"),
                "category": record.get("category"),
                "security_level": record.get("security_level"),
                "confidence": confidence,
                "detection_quality": record.get("detection_quality"),
                "evidence": candidate.evidence.as_dict(),
                "reasons": _build_reasons(candidate, group_size),
                "_specificity": _specificity(candidate.evidence.signature()),
            }
        )

    # Step 5: deterministic sort.
    #   confidence DESC, specificity DESC, hashcat_mode ASC, name ASC
    # (name ASC is an additional deterministic fallback for the rare
    # case hashcat_mode is also null/equal, ensuring stable output.)
    def _sort_key(item: Dict[str, Any]):
        mode = item.get("hashcat_mode")
        mode_sort = mode if isinstance(mode, (int, float)) else float("inf")
        return (
            -item["confidence"],
            -item["_specificity"],
            mode_sort,
            str(item.get("name") or ""),
        )

    results.sort(key=_sort_key)

    for item in results:
        del item["_specificity"]

    return results
