"""
backend/detector.py

Structural, purely-offline hash-format candidate generation for HashFox.

This module takes a single unknown hash/password-representation string
plus the loaded format database (see :mod:`backend.database`) and
produces a list of structurally plausible *candidates*, each annotated
with the raw evidence that supports it.

This module does NOT compute confidence scores or perform ambiguity
adjustment -- that is the responsibility of :mod:`backend.scoring`.
Keeping the two separated means detector.py only ever answers
"could this structurally be a match, and why", while scoring.py answers
"how confident should we be, given everyone who could match".

No network access. No hashing. No cracking. Pure string/regex/length
structural analysis against locally-loaded metadata.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Pattern

# Hard ceiling on input size to avoid pathological regex/processing cost
# on adversarial or accidental huge pastes. This is generous enough for
# any real hash/encoded-credential representation (the longest realistic
# formats are a few hundred characters).
MAX_INPUT_LENGTH = 10_000

# Detection quality values that must never be surfaced by automatic
# detection, regardless of how well they might otherwise structurally
# match.
_EXCLUDED_DETECTION_QUALITIES = {"reference_only"}

# Character-set checkers. Each predicate returns True if every character
# in `s` is compatible with the named character set. Unknown / unmapped
# character_set values are treated as "cannot verify" (see
# `charset_matches`) rather than silently matching everything.
_HEX_RE = re.compile(r"^[0-9a-fA-F]*$")
_DECIMAL_RE = re.compile(r"^[0-9]*$")
_ALNUM_RE = re.compile(r"^[0-9a-zA-Z]*$")
_STD_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]*$")
_URLSAFE_BASE64_RE = re.compile(r"^[A-Za-z0-9\-_=]*$")
# crypt()-style base64 alphabet: ./0-9A-Za-z (used by md5crypt, sha*crypt)
_CRYPT_BASE64_RE = re.compile(r"^[./0-9A-Za-z]*$")
# bcrypt uses the same crypt-base64 alphabet for its payload.
_BCRYPT_BASE64_RE = re.compile(r"^[./0-9A-Za-z]*$")
_PRINTABLE_ASCII_RE = re.compile(r"^[\x20-\x7e]*$")

_CHARSET_CHECKERS: Dict[str, Pattern[str]] = {
    "hex": _HEX_RE,
    "hexadecimal": _HEX_RE,
    "decimal": _DECIMAL_RE,
    "numeric": _DECIMAL_RE,
    "alnum": _ALNUM_RE,
    "alphanumeric": _ALNUM_RE,
    "base64": _STD_BASE64_RE,
    "base64url": _URLSAFE_BASE64_RE,
    "crypt-base64": _CRYPT_BASE64_RE,
    "base64-bcrypt": _BCRYPT_BASE64_RE,
    "printable-ascii": _PRINTABLE_ASCII_RE,
    "ascii": _PRINTABLE_ASCII_RE,
}


def charset_matches(value: str, character_set: Optional[str]) -> Optional[bool]:
    """Check whether `value` is compatible with a named character set.

    Args:
        value: The (already-normalized) candidate string.
        character_set: The character_set field from a database record.
            May be None/empty/unrecognized.

    Returns:
        True if every character in `value` fits the named set,
        False if it does not, or None if the character_set value is
        missing/unrecognized and therefore cannot be verified. Callers
        must treat None as "no supporting evidence", never as a match.
    """
    if not character_set:
        return None
    checker = _CHARSET_CHECKERS.get(character_set.strip().lower())
    if checker is None:
        return None
    return bool(checker.match(value))


@dataclass
class Evidence:
    """Structural evidence collected for a single candidate record."""

    regex_match: bool = False
    prefix_match: bool = False
    exact_length_match: bool = False
    length_range_match: bool = False
    charset_match: bool = False
    separator_match: bool = False
    regex_error: bool = False

    def as_dict(self) -> Dict[str, bool]:
        return {
            "regex_match": self.regex_match,
            "prefix_match": self.prefix_match,
            "exact_length_match": self.exact_length_match,
            "length_range_match": self.length_range_match,
            "charset_match": self.charset_match,
            "separator_match": self.separator_match,
        }

    def signature(self) -> tuple:
        """A hashable tuple summarizing which evidence flags are true.

        Used by scoring.py to group structurally-indistinguishable
        candidates for ambiguity adjustment.
        """
        return (
            self.regex_match,
            self.prefix_match,
            self.exact_length_match,
            self.length_range_match,
            self.charset_match,
            self.separator_match,
        )


@dataclass
class Candidate:
    """A structurally plausible format match, with supporting evidence."""

    record: Dict[str, Any]
    evidence: Evidence
    notes: List[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.record.get("name", "Unknown")

    @property
    def hashcat_mode(self) -> Any:
        return self.record.get("hashcat_mode")


def normalize_input(raw_input: str) -> str:
    """Normalize raw user input prior to structural analysis.

    - Strips leading/trailing whitespace (including Unicode whitespace).
    - Leaves internal characters untouched, since separators and casing
      can be structurally meaningful (e.g. hex case, `$` delimiters).

    Args:
        raw_input: The raw string supplied by the caller.

    Returns:
        str: The normalized string, suitable for structural analysis.
    """
    if raw_input is None:
        return ""
    return raw_input.strip()


def _prefix_match(value: str, prefixes: Optional[List[str]]) -> bool:
    if not prefixes:
        return False
    return any(bool(p) and value.startswith(p) for p in prefixes)


def _exact_length_match(value: str, record: Dict[str, Any]) -> bool:
    length = record.get("length")
    if length is None:
        return False
    try:
        return len(value) == int(length)
    except (TypeError, ValueError):
        return False


def _length_range_match(value: str, record: Dict[str, Any]) -> bool:
    min_len = record.get("min_length")
    max_len = record.get("max_length")
    if min_len is None or max_len is None:
        return False
    try:
        min_len = int(min_len)
        max_len = int(max_len)
    except (TypeError, ValueError):
        return False
    if min_len == max_len:
        # This is really an "exact length" signal, not a meaningful
        # range; exact_length_match already covers it. Avoid
        # double-counting a single-value range as a distinct signal.
        return False
    return min_len <= len(value) <= max_len


def _separator_match(value: str, separators: Optional[List[str]]) -> bool:
    if not separators:
        return False
    return any(bool(sep) and sep in value for sep in separators)


def _safe_regex_match(value: str, pattern: Optional[str]) -> tuple:
    """Attempt to match `value` against `pattern` without ever raising.

    Returns:
        (matched: bool, had_error: bool)
    """
    if not pattern:
        return False, False
    try:
        compiled = re.compile(pattern)
    except re.error:
        return False, True
    try:
        return bool(compiled.match(value)), False
    except re.error:
        return False, True


def _passes_structural_gate(evidence: Evidence) -> bool:
    """Decide whether evidence is meaningful enough to accept a candidate.

    A candidate must not be accepted purely on a generic signal such as
    "character set matched". This function encodes HashFox's gating
    policy: acceptance requires at least one defensible structural
    combination.
    """
    if evidence.prefix_match:
        return True
    if evidence.regex_match:
        return True
    if evidence.exact_length_match and evidence.charset_match:
        return True
    if evidence.length_range_match and evidence.separator_match:
        return True
    # Exact length alone (no charset confirmation) is too weak; charset
    # alone is too weak; length range alone is too weak. All rejected
    # implicitly by falling through to False.
    return False


def detect(raw_input: str, records: List[Dict[str, Any]]) -> List[Candidate]:
    """Generate structurally plausible candidates for `raw_input`.

    Args:
        raw_input: The unknown hash / encoded credential string.
        records: The full list of format records from the database.

    Returns:
        List[Candidate]: All records that pass the structural gate,
        each with its collected Evidence. Order is NOT final ranking
        order -- that is scoring.py's job. Records with
        detection_quality == "reference_only" are always excluded.
    """
    value = normalize_input(raw_input)

    if not value:
        return []

    if len(value) > MAX_INPUT_LENGTH:
        # Controlled handling of pathological input: do not attempt
        # structural analysis on it, and do not crash.
        return []

    # Guard against surprising Unicode input (e.g. combining marks,
    # exotic scripts) breaking length-based heuristics in confusing
    # ways. We do not reject Unicode input -- some legitimate encoded
    # representations may contain non-ASCII bytes when mispasted -- we
    # simply ensure the string is well-formed for iteration/regex use.
    try:
        unicodedata.normalize("NFC", value)
    except (TypeError, ValueError):
        # If normalization itself fails for some reason, fall back to
        # the raw value; regex/length checks below are still safe.
        pass

    candidates: List[Candidate] = []

    for record in records:
        if not isinstance(record, dict):
            continue

        if record.get("detection_quality") in _EXCLUDED_DETECTION_QUALITIES:
            continue

        regex_ok, regex_error = _safe_regex_match(value, record.get("regex"))

        evidence = Evidence(
            regex_match=regex_ok,
            regex_error=regex_error,
            prefix_match=_prefix_match(value, record.get("prefixes")),
            exact_length_match=_exact_length_match(value, record),
            length_range_match=_length_range_match(value, record),
            charset_match=bool(
                charset_matches(value, record.get("character_set"))
            ),
            separator_match=_separator_match(value, record.get("separators")),
        )

        if not _passes_structural_gate(evidence):
            continue

        notes: List[str] = []
        if regex_error:
            notes.append(
                "Record contained an invalid regex; regex evidence was "
                "skipped for this candidate."
            )

        candidates.append(Candidate(record=record, evidence=evidence, notes=notes))

    return candidates
