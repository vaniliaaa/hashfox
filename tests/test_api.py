"""
tests/test_api.py

Tests for backend.app FastAPI endpoints, using FastAPI's TestClient
(no real network, no real server process).
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from backend.app import app
from backend.detector import MAX_INPUT_LENGTH

client = TestClient(app)

MD5_LOOKING_HASH = "8743b52063cd84097a65d1633f5c74f5"
BCRYPT_HASH = "$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6"


# ---------------------------------------------------------------------------
# 1. GET / returns 200
# ---------------------------------------------------------------------------
def test_root_returns_200():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


# ---------------------------------------------------------------------------
# 2. GET /health returns healthy state
# ---------------------------------------------------------------------------
def test_health_returns_ok():
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "HashFox"


# ---------------------------------------------------------------------------
# 3. POST /api/analyze with 32-hex returns candidates
# ---------------------------------------------------------------------------
def test_analyze_32_hex_returns_candidates():
    response = client.post("/api/analyze", json={"hash": MD5_LOOKING_HASH})
    assert response.status_code == 200
    body = response.json()
    assert body["candidate_count"] > 1
    names = {c["name"] for c in body["candidates"]}
    assert {"MD5", "NTLM", "MD4"}.issubset(names)


# ---------------------------------------------------------------------------
# 4. Ambiguous result remains ambiguous
# ---------------------------------------------------------------------------
def test_analyze_32_hex_is_ambiguous():
    response = client.post("/api/analyze", json={"hash": MD5_LOOKING_HASH})
    body = response.json()
    assert body["ambiguous"] is True
    assert body["ambiguity_message"]


# ---------------------------------------------------------------------------
# 5. bcrypt analysis
# ---------------------------------------------------------------------------
def test_analyze_bcrypt():
    response = client.post("/api/analyze", json={"hash": BCRYPT_HASH})
    assert response.status_code == 200
    body = response.json()
    assert body["ambiguous"] is False
    assert body["top_candidate"] is not None
    assert "bcrypt" in body["top_candidate"]["name"].lower()


# ---------------------------------------------------------------------------
# 6. POST /api/pentest returns command targets
# ---------------------------------------------------------------------------
def test_pentest_returns_targets():
    response = client.post("/api/pentest", json={"hash": MD5_LOOKING_HASH})
    assert response.status_code == 200
    body = response.json()
    assert body["targets"]
    assert body["ambiguous"] is True
    assert body["warning"]


# ---------------------------------------------------------------------------
# 7. MD5/NTLM command data remains correct
# ---------------------------------------------------------------------------
def test_pentest_md5_and_ntlm_commands_correct():
    response = client.post("/api/pentest", json={"hash": MD5_LOOKING_HASH})
    body = response.json()
    by_name = {t["name"]: t for t in body["targets"]}

    assert by_name["MD5"]["hashcat_commands"]["dictionary"] == (
        "hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt"
    )
    assert by_name["MD5"]["john_command"] == (
        "john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt"
    )
    assert by_name["NTLM"]["hashcat_commands"]["dictionary"] == (
        "hashcat -m 1000 -a 0 hash.txt /usr/share/wordlists/rockyou.txt"
    )
    assert by_name["NTLM"]["john_command"] == (
        "john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt"
    )


# ---------------------------------------------------------------------------
# 8. Empty hash validation
# ---------------------------------------------------------------------------
def test_analyze_empty_hash_returns_validation_error():
    response = client.post("/api/analyze", json={"hash": ""})
    assert response.status_code == 422


def test_analyze_whitespace_only_hash_returns_validation_error():
    response = client.post("/api/analyze", json={"hash": "   "})
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# 9. Overlong input validation
# ---------------------------------------------------------------------------
def test_analyze_overlong_hash_returns_validation_error():
    huge = "a" * (MAX_INPUT_LENGTH + 100)
    response = client.post("/api/analyze", json={"hash": huge})
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# 10. Malformed JSON
# ---------------------------------------------------------------------------
def test_analyze_malformed_json_returns_error():
    response = client.post(
        "/api/analyze",
        content="{not valid json",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code in (400, 422)


def test_analyze_missing_hash_field_returns_validation_error():
    response = client.post("/api/analyze", json={})
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# 11. Custom hash_file/wordlist reaches generated commands safely
# ---------------------------------------------------------------------------
def test_pentest_custom_hash_file_and_wordlist_are_quoted():
    response = client.post(
        "/api/pentest",
        json={
            "hash": BCRYPT_HASH,
            "hash_file": "My hashes/hash.txt",
            "wordlist": "/tmp/my words.txt",
        },
    )
    assert response.status_code == 200
    body = response.json()
    target = body["targets"][0]
    command = target["hashcat_commands"]["dictionary"]
    assert "'My hashes/hash.txt'" in command
    assert "'/tmp/my words.txt'" in command


def test_pentest_shell_metacharacters_are_neutralized():
    response = client.post(
        "/api/pentest",
        json={"hash": BCRYPT_HASH, "hash_file": "hash.txt;whoami"},
    )
    assert response.status_code == 200
    body = response.json()
    command = body["targets"][0]["hashcat_commands"]["dictionary"]
    assert "'hash.txt;whoami'" in command


def test_pentest_rules_and_mask_reach_commands():
    response = client.post(
        "/api/pentest",
        json={"hash": BCRYPT_HASH, "rules_file": "best64.rule", "mask": "?d?d?d?d"},
    )
    assert response.status_code == 200
    body = response.json()
    target = body["targets"][0]
    assert "best64.rule" in target["hashcat_commands"]["rules"]
    assert target["hashcat_commands"]["mask"] is not None


# ---------------------------------------------------------------------------
# Additional controlled-error coverage
# ---------------------------------------------------------------------------
def test_pentest_empty_hash_returns_validation_error():
    response = client.post("/api/pentest", json={"hash": ""})
    assert response.status_code == 422


def test_pentest_missing_hash_field_returns_validation_error():
    response = client.post("/api/pentest", json={})
    assert response.status_code == 422


def test_static_files_are_served():
    css_response = client.get("/static/style.css")
    assert css_response.status_code == 200

    js_response = client.get("/static/script.js")
    assert js_response.status_code == 200


def test_no_stack_trace_leaks_on_bad_route():
    response = client.get("/this-route-does-not-exist")
    assert response.status_code == 404
    assert "Traceback" not in response.text


# ---------------------------------------------------------------------------
# Favicon regression (Web Issue 4)
# ---------------------------------------------------------------------------
def test_favicon_ico_is_served():
    response = client.get("/favicon.ico")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")


def test_favicon_static_asset_is_served():
    response = client.get("/static/favicon.svg")
    assert response.status_code == 200
