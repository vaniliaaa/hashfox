"""
backend/app.py

FastAPI application for HashFox.

This module is a thin HTTP layer only. It does not implement any
detection, scoring, or pentest-command logic itself -- it exclusively
calls into the already-completed:

    backend.analyzer.analyze_hash
    backend.pentest.build_pentest_assistance

and serves the static frontend (frontend/index.html, style.css,
script.js).

Run from the project root with:

    uvicorn backend.app:app --reload

No hash cracking, no command execution, no network calls of any kind
happen anywhere in this module.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from backend import __version__, analyzer, database, pentest
from backend.detector import MAX_INPUT_LENGTH

logger = logging.getLogger("hashfox")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"

app = FastAPI(
    title="HashFox",
    description="Smart Hash Intelligence & Pentest Assistant",
    version=__version__,
)


# ---------------------------------------------------------------------------
# Database loading
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def get_records() -> List[Dict[str, Any]]:
    """Load (and cache) the offline HashFox database for the app's lifetime.

    Cached with lru_cache so the JSON file is parsed once per process,
    not once per request. Raises database.DatabaseError if the database
    cannot be loaded; callers are expected to convert that into a clean
    HTTP 500 rather than letting a stack trace reach the client.
    """
    return database.load_database()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class AnalyzeRequest(BaseModel):
    """Request body for POST /api/analyze."""

    hash: str = Field(
        ...,
        min_length=1,
        max_length=MAX_INPUT_LENGTH,
        description="The unknown hash / encoded credential string to analyze.",
    )

    @field_validator("hash")
    @classmethod
    def _hash_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("hash must not be empty or whitespace-only")
        return value


class PentestRequest(BaseModel):
    """Request body for POST /api/pentest."""

    hash: str = Field(
        ...,
        min_length=1,
        max_length=MAX_INPUT_LENGTH,
        description="The unknown hash / encoded credential string to analyze.",
    )
    hash_file: str = Field(
        default=pentest.DEFAULT_HASH_FILE,
        max_length=4096,
        description="Path to the file that will contain the hash(es).",
    )
    wordlist: str = Field(
        default=pentest.DEFAULT_WORDLIST,
        max_length=4096,
        description="Path to the wordlist file.",
    )
    rules_file: Optional[str] = Field(
        default=None,
        max_length=4096,
        description="Optional path to a Hashcat rules file.",
    )
    mask: Optional[str] = Field(
        default=None,
        max_length=1024,
        description="Optional Hashcat mask string, e.g. ?d?d?d?d.",
    )

    @field_validator("hash")
    @classmethod
    def _hash_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("hash must not be empty or whitespace-only")
        return value

    @field_validator("hash_file", "wordlist")
    @classmethod
    def _path_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("value must not be empty or whitespace-only")
        return value


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler so no Python stack trace ever reaches the client."""
    logger.exception("Unhandled error while processing %s", request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error. Please try again."},
    )


# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/")
async def serve_index() -> FileResponse:
    """Serve the HashFox single-page frontend."""
    index_path = FRONTEND_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Frontend not found.")
    return FileResponse(str(index_path))


@app.get("/favicon.ico")
async def favicon() -> FileResponse:
    """Serve the HashFox favicon at the conventional /favicon.ico path.

    Browsers request this path automatically regardless of any <link
    rel="icon"> tag; without this route that request would otherwise
    404. The underlying file is a plain SVG -- served with an explicit
    SVG media type, which modern browsers render correctly at this URL.
    """
    favicon_path = FRONTEND_DIR / "favicon.svg"
    if not favicon_path.exists():
        raise HTTPException(status_code=404, detail="Favicon not found.")
    return FileResponse(str(favicon_path), media_type="image/svg+xml")


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/health")
async def health() -> Dict[str, str]:
    """Simple health check."""
    return {"status": "ok", "service": "HashFox"}


# ---------------------------------------------------------------------------
# Analyze
# ---------------------------------------------------------------------------
@app.post("/api/analyze")
async def api_analyze(payload: AnalyzeRequest) -> Dict[str, Any]:
    """Run the existing detection/scoring pipeline on a supplied hash."""
    try:
        records = get_records()
    except database.DatabaseError as exc:
        logger.error("Database load failure: %s", exc)
        raise HTTPException(status_code=500, detail="HashFox database unavailable.") from exc

    result = analyzer.analyze_hash(payload.hash, records)
    return result


# ---------------------------------------------------------------------------
# Pentest assistance
# ---------------------------------------------------------------------------
@app.post("/api/pentest")
async def api_pentest(payload: PentestRequest) -> Dict[str, Any]:
    """Run analysis, then prepare Hashcat/John command guidance.

    This endpoint never executes anything -- it returns plain command
    strings for the operator to review and run themselves.
    """
    try:
        records = get_records()
    except database.DatabaseError as exc:
        logger.error("Database load failure: %s", exc)
        raise HTTPException(status_code=500, detail="HashFox database unavailable.") from exc

    analysis = analyzer.analyze_hash(payload.hash, records)
    assistance = pentest.build_pentest_assistance(
        analysis,
        hash_file=payload.hash_file,
        wordlist=payload.wordlist,
        rules_file=payload.rules_file,
        mask=payload.mask,
    )
    return assistance
