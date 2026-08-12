"""
tests/test_banner.py

Focused tests for backend.banner: the compact fox-head logo, the
block-letter HASHFOX wordmark, the startup animation, and the final
banner rendering. All sleeps are injected as no-ops so these tests run
instantly regardless of the real animation timing.
"""

from __future__ import annotations

from rich.console import Console

from backend import __version__, banner


def _plain_console(force_terminal: bool = False) -> Console:
    return Console(force_terminal=force_terminal, no_color=True, width=80, highlight=False)


# ---------------------------------------------------------------------------
# Fox-head logo (no body, no tail)
# ---------------------------------------------------------------------------
def test_fox_head_frames_are_original_and_progressive():
    assert len(banner.FOX_HEAD_FRAMES) == 3
    lengths = [len(frame) for frame in banner.FOX_HEAD_FRAMES]
    assert lengths == sorted(lengths)
    assert len(set(banner.FOX_HEAD_FRAMES)) == 3


def test_fox_head_is_compact_and_headless_of_body():
    # At most 8 lines, per the approved design.
    lines = banner.FOX_HEAD.splitlines()
    assert 1 <= len(lines) <= 8
    # No body/tail markers from the earlier full-body design should
    # reappear (e.g. the old seated-body/tail characters).
    assert "o)--<" not in banner.FOX_HEAD
    assert "(_|" not in banner.FOX_HEAD


def test_fox_head_final_frame_matches_approved_design():
    expected = (
        "     /\\   /\\\n"
        "    /  \\_/  \\\n"
        "   |  o   o  |\n"
        "    \\   ^   /\n"
        "     \\_____/"
    )
    assert banner.FOX_HEAD == expected


# ---------------------------------------------------------------------------
# HASHFOX block wordmark (no figlet dependency)
# ---------------------------------------------------------------------------
def test_wordmark_renders_without_external_dependency():
    # render_wordmark is pure Python / an embedded bitmap font -- no
    # subprocess, no figlet import needed. If this call succeeds at
    # all, that guarantee holds.
    wordmark = banner.render_wordmark("HASHFOX")
    assert wordmark
    assert wordmark == banner.HASHFOX_WORDMARK


def test_wordmark_is_six_rows_tall():
    rows = banner.HASHFOX_WORDMARK.splitlines()
    assert len(rows) == 6


def test_wordmark_rows_are_consistent_width():
    rows = banner.HASHFOX_WORDMARK.splitlines()
    widths = {len(row) for row in rows}
    assert len(widths) == 1  # all rows the same width


def test_wordmark_uses_block_character():
    assert "\u2588" in banner.HASHFOX_WORDMARK


# ---------------------------------------------------------------------------
# should_animate
# ---------------------------------------------------------------------------
def test_should_animate_respects_no_banner_flag():
    console = _plain_console(force_terminal=True)
    assert banner.should_animate(console, no_banner=True) is False


def test_should_animate_respects_non_terminal():
    console = _plain_console(force_terminal=False)
    assert banner.should_animate(console, no_banner=False) is False


def test_should_animate_true_for_terminal_without_no_banner():
    console = _plain_console(force_terminal=True)
    assert banner.should_animate(console, no_banner=False) is True


# ---------------------------------------------------------------------------
# Final banner content
# ---------------------------------------------------------------------------
def test_print_final_banner_contains_required_fields(capsys):
    console = _plain_console()
    banner.print_final_banner(console, records_count=284)
    out = capsys.readouterr().out

    # Fox head + wordmark
    assert "/\\   /\\" in out
    assert "\u2588" in out  # wordmark block characters

    # Branding text
    assert "Smart Hash Intelligence & Pentest Assistant" in out
    assert "Identify" in out
    assert "Analyze" in out
    assert "Explain" in out
    assert "Prepare" in out

    # Approved status line wording
    assert "284 signatures loaded" in out
    assert "Engine READY" in out

    # Version / offline line
    assert f"v{__version__}" in out
    assert "OFFLINE" in out


def test_print_final_banner_has_no_full_body_fox_or_tail(capsys):
    console = _plain_console()
    banner.print_final_banner(console, records_count=284)
    out = capsys.readouterr().out
    assert "o)--<" not in out
    assert "(_|" not in out


# ---------------------------------------------------------------------------
# run_startup: animated vs non-animated paths
# ---------------------------------------------------------------------------
def test_run_startup_non_animated_path_no_sleep_calls(capsys):
    sleep_calls = []
    console = _plain_console(force_terminal=False)
    banner.run_startup(
        console, animate=True, sleep_fn=lambda s: sleep_calls.append(s), records_count=284
    )
    # Non-terminal console => animation is skipped regardless of animate=True.
    assert sleep_calls == []
    out = capsys.readouterr().out
    assert "284 signatures loaded" in out


def test_run_startup_animated_path_calls_sleep_and_stays_within_budget(capsys):
    sleep_calls = []
    console = _plain_console(force_terminal=True)
    banner.run_startup(
        console, animate=True, sleep_fn=lambda s: sleep_calls.append(s), records_count=284
    )
    # 3 fox-head frames + 1 wordmark reveal + 2 readiness checks = 6 sleeps.
    assert len(sleep_calls) == 6
    # Approved total animation budget: ~0.8-1.2 seconds.
    assert 0.8 <= sum(sleep_calls) <= 1.2

    out = capsys.readouterr().out
    assert "284 signatures loaded" in out
    assert "Engine READY" in out
    assert "\u2588" in out  # final wordmark rendered after animation


def test_run_startup_respects_animate_false(capsys):
    sleep_calls = []
    console = _plain_console(force_terminal=True)
    banner.run_startup(
        console, animate=False, sleep_fn=lambda s: sleep_calls.append(s), records_count=284
    )
    assert sleep_calls == []
    out = capsys.readouterr().out
    assert "284 signatures loaded" in out


def test_banner_does_not_crash_with_no_color_non_tty(capsys):
    # Simulates piping HashFox's output to a file or another process.
    console = Console(force_terminal=False, no_color=True, width=80, highlight=False)
    banner.run_startup(console, animate=True, sleep_fn=lambda *_: None, records_count=284)
    out = capsys.readouterr().out
    assert "\x1b[" not in out  # no raw ANSI escape codes leaked into plain output
    assert "284 signatures loaded" in out


# ---------------------------------------------------------------------------
# Real-terminal regression test: intermediate animation frames must not
# accumulate in the terminal's scrollback, and the final visible screen
# must contain exactly one banner. A plain StringIO capture cannot prove
# this (ANSI cursor-movement codes only take effect when a real pty's
# line discipline processes them), so this test drives the animation
# through an actual pseudo-terminal and replays the captured bytes
# through a terminal emulator (pyte) to see what a user would really see.
# ---------------------------------------------------------------------------
import os

import pytest

pyte = pytest.importorskip("pyte", reason="pyte is only needed for this real-terminal regression test")


@pytest.mark.skipif(os.name != "posix", reason="pty is only available on POSIX platforms")
def test_animation_does_not_duplicate_frames_on_a_real_terminal():
    import pty
    import select

    master_fd, slave_fd = pty.openpty()
    slave_file = os.fdopen(slave_fd, "w", closefd=True)

    try:
        console = Console(file=slave_file, force_terminal=True, width=80, height=40, highlight=False)
        banner.run_startup(console, animate=True, sleep_fn=lambda *_: None, records_count=284)
    finally:
        slave_file.close()

    data = b""
    try:
        while True:
            ready, _, _ = select.select([master_fd], [], [], 0.5)
            if not ready:
                break
            try:
                chunk = os.read(master_fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            data += chunk
    finally:
        os.close(master_fd)

    screen = pyte.HistoryScreen(80, 40, history=200)
    stream = pyte.ByteStream(screen)
    stream.feed(data)

    # No intermediate frame should have been pushed into scrollback --
    # everything before the final banner must have been redrawn in place
    # and erased, not scrolled past.
    assert len(screen.history.top) == 0

    visible_lines = [line.rstrip() for line in screen.display]
    visible_text = "\n".join(visible_lines)

    # The final on-screen content contains exactly one copy of each
    # banner element, not several stacked/duplicated copies.
    assert visible_text.count("Smart Hash Intelligence & Pentest Assistant") == 1
    assert visible_text.count("Identify") == 1
    assert visible_text.count("284 signatures loaded") == 1
    assert visible_text.count("Engine READY") == 1
    assert visible_text.count("OFFLINE") == 1

    # The fox-head logo line ("     /\\   /\\") appears exactly once on
    # the final screen -- not once per animation frame.
    assert visible_text.count("/\\   /\\") == 1
