"""
tests/test_cli.py

Tests for backend.cli, HashFox's terminal interface.

CLI functions are invoked directly (main(argv)) rather than via
subprocess, and stdout is captured with pytest's capsys fixture. Rich's
Console automatically disables ANSI styling when stdout is not a
terminal (as under pytest), so assertions can check plain substrings.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend import __version__, cli

MD5_LOOKING_HASH = "8846f7eaee8fb117ad06bdd830b7586c"
BCRYPT_HASH = "$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6"


# ---------------------------------------------------------------------------
# 1 & 2. --help / --version
# ---------------------------------------------------------------------------
def test_help_exits_zero_and_lists_commands(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--help"])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "analyze" in out
    assert "scan" in out
    assert "lookup" in out
    assert "serve" in out


def test_version_exits_zero_and_prints_version(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--version"])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert __version__ in out
    assert "HashFox" in out


def test_bare_invocation_enters_interactive_console(monkeypatch, capsys):
    """1. Bare `hashfox` enters the interactive console (not just --help)."""
    inputs = iter(["exit"])

    def fake_input(prompt=""):
        print(prompt, end="")
        return next(inputs)

    monkeypatch.setattr("builtins.input", fake_input)
    exit_code = cli.main(["--no-banner"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "hashfox ❯" in out
    assert "Goodbye" in out


def test_no_banner_skips_animation_but_still_shows_banner(monkeypatch, capsys):
    """2. --no-banner skips the animated sequence but still enters the console."""
    calls = {"sleep": 0}
    monkeypatch.setattr("backend.banner.time.sleep", lambda *_: calls.__setitem__("sleep", calls["sleep"] + 1))
    inputs = iter(["exit"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))

    exit_code = cli.main(["--no-banner"])
    assert exit_code == 0
    out = capsys.readouterr().out
    # Final banner content still appears...
    assert "\u2588" in out  # HASHFOX block wordmark rendered
    assert "Engine READY" in out
    # ...but no animation delays were triggered.
    assert calls["sleep"] == 0


def test_analyze_command_does_not_animate(monkeypatch, capsys):
    """3. `hashfox analyze HASH` must not trigger the startup animation."""
    def fail_if_called(*args, **kwargs):
        raise AssertionError("run_startup must not be called for direct subcommands")

    monkeypatch.setattr("backend.cli.banner.run_startup", fail_if_called)
    exit_code = cli.main(["analyze", MD5_LOOKING_HASH])
    assert exit_code == 0


def test_version_flag_does_not_animate(monkeypatch, capsys):
    """4. `hashfox --version` must not trigger the startup animation."""
    def fail_if_called(*args, **kwargs):
        raise AssertionError("run_startup must not be called for --version")

    monkeypatch.setattr("backend.cli.banner.run_startup", fail_if_called)
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--version"])
    assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# Interactive console commands (banner stage tests 5-8)
# ---------------------------------------------------------------------------
def test_interactive_help_command(monkeypatch, capsys):
    """5. interactive `help`."""
    inputs = iter(["help", "exit"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))
    exit_code = cli.main(["--no-banner"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Available commands" in out
    assert "analyze HASH" in out
    assert "lookup QUERY" in out


def test_interactive_version_command(monkeypatch, capsys):
    """6. interactive `version`."""
    inputs = iter(["version", "exit"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))
    exit_code = cli.main(["--no-banner"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert f"HashFox {__version__}" in out


def test_interactive_lookup_command(monkeypatch, capsys):
    """7. interactive `lookup MD5`."""
    inputs = iter(["lookup MD5", "exit"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))
    exit_code = cli.main(["--no-banner"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "MD5" in out
    assert "Category:" in out


def test_interactive_exit_command_ends_loop(monkeypatch, capsys):
    """8. interactive `exit` cleanly ends the console loop."""
    inputs = iter(["exit"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))
    exit_code = cli.main(["--no-banner"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Goodbye" in out


def test_interactive_quit_command_ends_loop(monkeypatch, capsys):
    inputs = iter(["quit"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))
    exit_code = cli.main(["--no-banner"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Goodbye" in out


def test_interactive_unknown_command_is_controlled(monkeypatch, capsys):
    inputs = iter(["frobnicate", "exit"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))
    exit_code = cli.main(["--no-banner"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Unknown command" in out


def test_interactive_analyze_command_reuses_existing_cli_logic(monkeypatch, capsys):
    inputs = iter([f"analyze {BCRYPT_HASH}", "exit"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))
    exit_code = cli.main(["--no-banner"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "bcrypt" in out.lower()


def test_interactive_eof_ends_loop_gracefully(monkeypatch, capsys):
    def raise_eof(prompt=""):
        raise EOFError

    monkeypatch.setattr("builtins.input", raise_eof)
    exit_code = cli.main(["--no-banner"])
    assert exit_code == 0


# ---------------------------------------------------------------------------
# 9. Banner rendering does not crash without color/TTY
# ---------------------------------------------------------------------------
def test_banner_renders_without_crashing_non_terminal(capsys):
    from rich.console import Console
    from backend import banner as banner_module

    console = Console(force_terminal=False, no_color=True, width=80)
    # Should not raise even though this console is not an interactive TTY.
    banner_module.run_startup(console, animate=True, sleep_fn=lambda *_: None, records_count=284)
    out = capsys.readouterr().out
    assert "\u2588" in out  # HASHFOX block wordmark rendered
    assert "Engine READY" in out


def test_banner_final_banner_plain_text_contains_expected_fields(capsys):
    from rich.console import Console
    from backend import banner as banner_module

    console = Console(force_terminal=False, no_color=True, width=80)
    banner_module.print_final_banner(console, records_count=284)
    out = capsys.readouterr().out
    assert "\u2588" in out  # HASHFOX block wordmark rendered
    assert "Smart Hash Intelligence & Pentest Assistant" in out
    assert "Identify" in out and "Analyze" in out and "Explain" in out and "Prepare" in out
    assert f"v{__version__}" in out
    assert "284 signatures" in out
    assert "Engine READY" in out




# ---------------------------------------------------------------------------
# 10. Existing full suite still passes
# ---------------------------------------------------------------------------
def test_previously_passing_analyze_still_works(capsys):
    exit_code = cli.main(["analyze", MD5_LOOKING_HASH])
    assert exit_code == 0


# ---------------------------------------------------------------------------
# 3 & 4. Analyze ambiguous 32-hex + ambiguity warning
# ---------------------------------------------------------------------------
def test_analyze_ambiguous_32_hex(capsys):
    exit_code = cli.main(["analyze", MD5_LOOKING_HASH])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "MD5" in out
    assert "NTLM" in out
    assert "MD4" in out
    assert "Ambiguous structure" in out
    assert "Verify" in out


# ---------------------------------------------------------------------------
# 5. Analyze bcrypt
# ---------------------------------------------------------------------------
def test_analyze_bcrypt(capsys):
    exit_code = cli.main(["analyze", BCRYPT_HASH])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "bcrypt" in out.lower()
    assert "Ambiguous structure" not in out


# ---------------------------------------------------------------------------
# 6, 7, 8, 9. analyze --pentest, commands appear correctly
# ---------------------------------------------------------------------------
def test_analyze_pentest_md5_hashcat_command(capsys):
    exit_code = cli.main(["analyze", MD5_LOOKING_HASH, "--pentest"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt" in out


def test_analyze_pentest_ntlm_hashcat_mode_1000(capsys):
    exit_code = cli.main(["analyze", MD5_LOOKING_HASH, "--pentest"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "hashcat -m 1000 -a 0 hash.txt /usr/share/wordlists/rockyou.txt" in out


def test_analyze_pentest_verified_john_command_appears(capsys):
    exit_code = cli.main(["analyze", MD5_LOOKING_HASH, "--pentest"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt" in out
    assert "john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt" in out


def test_analyze_pentest_shows_warning_and_fox_tip(capsys):
    exit_code = cli.main(["analyze", MD5_LOOKING_HASH, "--pentest"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Do not select a cracking mode blindly" in out
    assert "Fox Tip" in out


# ---------------------------------------------------------------------------
# 10 & 11. scan: multiple hashes, blank lines ignored
# ---------------------------------------------------------------------------
def test_scan_file_with_several_hashes_and_blank_lines(tmp_path: Path, capsys):
    scan_file = tmp_path / "hashes.txt"
    scan_file.write_text(
        f"{MD5_LOOKING_HASH}\n\n{BCRYPT_HASH}\n\n\nnot-a-real-hash!!!\n",
        encoding="utf-8",
    )

    exit_code = cli.main(["scan", str(scan_file)])
    assert exit_code == 0
    out = capsys.readouterr().out

    assert "[1]" in out
    assert "[3]" in out
    assert "[6]" in out
    assert "AMBIGUOUS" in out
    assert "bcrypt" in out.lower()
    assert "No match" in out
    assert "Analyzed: 3" in out
    assert "Ambiguous: 1" in out
    assert "No match: 1" in out


def test_scan_deterministic_line_numbering_skips_blanks(tmp_path: Path, capsys):
    scan_file = tmp_path / "hashes.txt"
    # Blank lines (including whitespace-only) at lines 1 and 3; real
    # content only at line 2.
    scan_file.write_text(f"\n{BCRYPT_HASH}\n   \n", encoding="utf-8")

    exit_code = cli.main(["scan", str(scan_file)])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "[2]" in out
    assert "[1]" not in out
    assert "[3]" not in out
    assert "Analyzed: 1" in out


# ---------------------------------------------------------------------------
# 12. scan handles file-not-found cleanly
# ---------------------------------------------------------------------------
def test_scan_missing_file_returns_controlled_error(tmp_path: Path, capsys):
    missing = tmp_path / "does-not-exist.txt"
    exit_code = cli.main(["scan", str(missing)])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "File not found" in out
    assert "Traceback" not in out


# ---------------------------------------------------------------------------
# 13 & 14. lookup MD5, case-insensitive
# ---------------------------------------------------------------------------
def test_lookup_md5(capsys):
    exit_code = cli.main(["lookup", "MD5"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "MD5" in out
    assert "Category:" in out
    assert "Hashcat Mode:" in out


def test_lookup_is_case_insensitive(capsys):
    exit_code_lower = cli.main(["lookup", "ntlm"])
    out_lower = capsys.readouterr().out
    exit_code_upper = cli.main(["lookup", "NTLM"])
    out_upper = capsys.readouterr().out

    assert exit_code_lower == 0
    assert exit_code_upper == 0
    assert "NTLM" in out_lower
    assert "NTLM" in out_upper


# ---------------------------------------------------------------------------
# 15. Unknown lookup returns controlled result
# ---------------------------------------------------------------------------
def test_lookup_unknown_query_is_controlled(capsys):
    exit_code = cli.main(["lookup", "definitely-not-a-real-format-xyz"])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "No matching formats found." in out
    assert "Traceback" not in out


# ---------------------------------------------------------------------------
# 16. Custom hash-file/wordlist options reach the Pentest Assistant
# ---------------------------------------------------------------------------
def test_custom_hash_file_and_wordlist_reach_pentest_output(capsys):
    exit_code = cli.main(
        [
            "analyze",
            BCRYPT_HASH,
            "--pentest",
            "--hash-file",
            "My hashes/hash.txt",
            "--wordlist",
            "/tmp/my words.txt",
        ]
    )
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "'My hashes/hash.txt'" in out
    assert "'/tmp/my words.txt'" in out


# ---------------------------------------------------------------------------
# 17. Malformed / empty user input is controlled
# ---------------------------------------------------------------------------
def test_analyze_empty_hash_is_controlled(capsys):
    exit_code = cli.main(["analyze", ""])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "Error" in out
    assert "Traceback" not in out


def test_analyze_whitespace_only_hash_is_controlled(capsys):
    exit_code = cli.main(["analyze", "   "])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "Error" in out


def test_lookup_empty_query_is_controlled(capsys):
    exit_code = cli.main(["lookup", ""])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "Error" in out


# ---------------------------------------------------------------------------
# 18. No cracking command is ever executed
# ---------------------------------------------------------------------------
def test_pentest_never_invokes_subprocess(monkeypatch, capsys):
    calls = []

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("subprocess must never be invoked by HashFox")

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(subprocess, "Popen", fake_run)
    monkeypatch.setattr("os.system", fake_run)

    exit_code = cli.main(["analyze", MD5_LOOKING_HASH, "--pentest"])
    assert exit_code == 0
    assert calls == []


# ---------------------------------------------------------------------------
# 19. Determinism
# ---------------------------------------------------------------------------
def test_analyze_output_is_deterministic(capsys):
    cli.main(["analyze", MD5_LOOKING_HASH])
    first = capsys.readouterr().out
    cli.main(["analyze", MD5_LOOKING_HASH])
    second = capsys.readouterr().out
    assert first == second


# ---------------------------------------------------------------------------
# 20. serve argument parsing without starting a permanent server
# ---------------------------------------------------------------------------
def test_serve_invokes_uvicorn_with_parsed_args(monkeypatch, capsys):
    calls = []

    class FakeUvicorn:
        @staticmethod
        def run(app_path, host=None, port=None, reload=None):
            calls.append({"app_path": app_path, "host": host, "port": port, "reload": reload})

    monkeypatch.setitem(__import__("sys").modules, "uvicorn", FakeUvicorn)

    exit_code = cli.main(["serve", "--host", "0.0.0.0", "--port", "9001"])
    assert exit_code == 0
    assert len(calls) == 1
    assert calls[0]["app_path"] == "backend.app:app"
    assert calls[0]["host"] == "0.0.0.0"
    assert calls[0]["port"] == 9001
    assert calls[0]["reload"] is False


def test_serve_default_arguments(monkeypatch):
    calls = []

    class FakeUvicorn:
        @staticmethod
        def run(app_path, host=None, port=None, reload=None):
            calls.append({"host": host, "port": port, "reload": reload})

    monkeypatch.setitem(__import__("sys").modules, "uvicorn", FakeUvicorn)

    exit_code = cli.main(["serve"])
    assert exit_code == 0
    assert calls[0]["host"] == "127.0.0.1"
    assert calls[0]["port"] == 8000
    assert calls[0]["reload"] is False
