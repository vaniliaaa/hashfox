"""
backend/database.py

Offline database loader for HashFox.

Responsible ONLY for locating, loading, and lightly validating the
hash-format database stored at ``database/hashes.json``. This module
performs no detection or scoring logic -- it simply hands back the raw
list of format records for :mod:`backend.detector` to consume.

Design goals:
    - Fully offline. No network access of any kind.
    - Deterministic path resolution relative to the project root, not
      the process's current working directory.
    - Clear, actionable error messages for missing/malformed data.
    - Never mutate the records it loads.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


class DatabaseError(Exception):
    """Raised when the HashFox format database cannot be loaded or is malformed."""


# The database file lives at <project_root>/database/hashes.json.
# This file lives at <project_root>/backend/database.py, so the project
# root is one directory up from this file's parent.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_DATABASE_PATH = _PROJECT_ROOT / "database" / "hashes.json"


def get_default_database_path() -> Path:
    """Return the default, project-root-relative path to hashes.json.

    Returns:
        Path: Absolute path to ``database/hashes.json`` resolved relative
        to the project root (i.e. independent of the current working
        directory the process happens to be launched from).
    """
    return _DEFAULT_DATABASE_PATH


def load_database(path: Path | str | None = None) -> List[Dict[str, Any]]:
    """Load the HashFox hash-format database from disk.

    This function performs no network access. It reads a single local
    JSON file, parses it, and validates that its top-level shape is a
    list of records. Individual record contents are intentionally NOT
    deeply validated here -- callers (e.g. the detector) are expected to
    treat individual fields defensively, since some fields may
    legitimately be null, missing, or empty.

    Args:
        path: Optional explicit path to a hashes.json file. If omitted,
            resolves to ``<project_root>/database/hashes.json``.

    Returns:
        List[Dict[str, Any]]: The raw list of format records, exactly as
        stored on disk (no mutation).

    Raises:
        DatabaseError: If the file is missing, unreadable, not valid
            UTF-8 JSON, or if its top-level structure is not a list.
    """
    resolved_path = Path(path) if path is not None else get_default_database_path()

    if not resolved_path.exists():
        raise DatabaseError(
            f"HashFox database not found at '{resolved_path}'. "
            "Expected a JSON file at database/hashes.json relative to "
            "the project root. This loader does not build or fetch the "
            "database -- see tools/build_hash_database.py."
        )

    if not resolved_path.is_file():
        raise DatabaseError(
            f"HashFox database path '{resolved_path}' exists but is not a file."
        )

    try:
        raw_text = resolved_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise DatabaseError(
            f"HashFox database at '{resolved_path}' is not valid UTF-8: {exc}"
        ) from exc
    except OSError as exc:
        raise DatabaseError(
            f"Could not read HashFox database at '{resolved_path}': {exc}"
        ) from exc

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise DatabaseError(
            f"HashFox database at '{resolved_path}' is not valid JSON: {exc}"
        ) from exc

    if not isinstance(data, list):
        raise DatabaseError(
            f"HashFox database at '{resolved_path}' must contain a top-level "
            f"JSON array of records, but found {type(data).__name__}."
        )

    for index, record in enumerate(data):
        if not isinstance(record, dict):
            raise DatabaseError(
                f"HashFox database record at index {index} is not a JSON "
                f"object (found {type(record).__name__})."
            )

    return data
