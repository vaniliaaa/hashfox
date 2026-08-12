"""
backend/banner.py

Original HashFox ASCII fox-head logo, block-letter wordmark, startup
animation, and final banner.

This module is purely presentational. It never touches detection,
scoring, analysis, or pentest logic, and it never executes anything
beyond writing to the terminal and sleeping for short, injectable
durations (so tests can run instantly with a no-op sleep function).

Design: a compact fox-HEAD-only logo (no body, no tail) paired with a
large block-character "HASHFOX" wordmark rendered from an embedded 5x6
bitmap font -- no external `figlet` binary or font file dependency.
"""

from __future__ import annotations

import time
from typing import Callable, Dict, List, Optional

from rich.console import Console, Group
from rich.live import Live
from rich.text import Text

from backend import __version__

FOX_ORANGE = "#ff7a30"
CYBER_GREEN = "#33e6a4"
MUTED = "#8a97a8"

DEFAULT_SIGNATURE_COUNT = 284

SleepFn = Callable[[float], None]

# ---------------------------------------------------------------------------
# Original compact fox-HEAD logo (created for HashFox; not copied from
# any existing artwork). No body, no tail -- just ears, a narrow face,
# eyes, and a simplified nose/chin so it reads as a clean logo mark
# rather than an illustration.
# ---------------------------------------------------------------------------
FOX_HEAD_FRAME_1 = r"""
     /\   /\
""".strip("\n")

FOX_HEAD_FRAME_2 = r"""
     /\   /\
    /  \_/  \
   |  o   o  |
""".strip("\n")

FOX_HEAD_FRAME_3 = r"""
     /\   /\
    /  \_/  \
   |  o   o  |
    \   ^   /
     \_____/
""".strip("\n")

FOX_HEAD_FRAMES = [FOX_HEAD_FRAME_1, FOX_HEAD_FRAME_2, FOX_HEAD_FRAME_3]
FOX_HEAD = FOX_HEAD_FRAME_3

# ---------------------------------------------------------------------------
# Embedded 5x6 block-letter font, used only to spell "HASHFOX". This is
# an original, minimal bitmap font defined directly in Python -- it has
# no dependency on the external `figlet` executable or any font file,
# so it renders identically after a plain `pip install -e .`.
# ---------------------------------------------------------------------------
_GLYPH_WIDTH = 5
_GLYPH_HEIGHT = 6

_FONT: Dict[str, List[str]] = {
    "H": [
        "#   #",
        "#   #",
        "#####",
        "#   #",
        "#   #",
        "#   #",
    ],
    "A": [
        " ### ",
        "#   #",
        "#   #",
        "#####",
        "#   #",
        "#   #",
    ],
    "S": [
        " ####",
        "#    ",
        " ### ",
        "    #",
        "    #",
        "#### ",
    ],
    "F": [
        "#####",
        "#    ",
        "#### ",
        "#    ",
        "#    ",
        "#    ",
    ],
    "O": [
        " ### ",
        "#   #",
        "#   #",
        "#   #",
        "#   #",
        " ### ",
    ],
    "X": [
        "#   #",
        "#   #",
        " ### ",
        "#   #",
        "#   #",
        "#   #",
    ],
}

_BLOCK_CHAR = "\u2588"  # █


def render_wordmark(word: str, block: str = _BLOCK_CHAR) -> str:
    """Render `word` as a large block-letter wordmark.

    Only characters present in the embedded font are supported; this
    is intentionally minimal since HashFox only ever renders the fixed
    word "HASHFOX". Unknown characters are skipped.

    Args:
        word: The word to render (e.g. "HASHFOX").
        block: The fill character used for "on" pixels.

    Returns:
        str: A multi-line string, `_GLYPH_HEIGHT` rows tall.
    """
    letters = [_FONT[ch] for ch in word if ch in _FONT]
    if not letters:
        return ""

    rows = []
    for row_index in range(_GLYPH_HEIGHT):
        row = " ".join(letter[row_index] for letter in letters)
        rows.append(row)

    text = "\n".join(rows)
    return text.replace("#", block)


HASHFOX_WORDMARK = render_wordmark("HASHFOX")


def should_animate(console: Console, no_banner: bool) -> bool:
    """Decide whether the startup animation should play.

    Animation is skipped whenever the caller explicitly asked to skip
    it (--no-banner) or when stdout is not an interactive terminal
    (e.g. piped output, redirected file, or a test harness).
    """
    if no_banner:
        return False
    return bool(getattr(console, "is_terminal", False))


def print_final_banner(console: Console, records_count: int = DEFAULT_SIGNATURE_COUNT) -> None:
    """Print the static final HashFox banner (fox-head logo + wordmark + status)."""
    console.print()
    console.print(FOX_HEAD, style=f"bold {FOX_ORANGE}", markup=False)
    console.print()
    console.print(HASHFOX_WORDMARK, style=f"bold {FOX_ORANGE}", markup=False)
    console.print()
    console.print("Smart Hash Intelligence & Pentest Assistant", style=MUTED)
    console.print()
    console.print(
        f"[{CYBER_GREEN}]Identify[/{CYBER_GREEN}] • "
        f"[{CYBER_GREEN}]Analyze[/{CYBER_GREEN}] • "
        f"[{CYBER_GREEN}]Explain[/{CYBER_GREEN}] • "
        f"[{CYBER_GREEN}]Prepare[/{CYBER_GREEN}]"
    )
    console.print()
    console.print(
        f"[bold {CYBER_GREEN}]✓[/bold {CYBER_GREEN}] {records_count} signatures loaded"
        f"       [bold {CYBER_GREEN}]✓[/bold {CYBER_GREEN}] Engine READY"
    )
    console.print()
    console.print(f"v{__version__} • [bold {CYBER_GREEN}]OFFLINE[/bold {CYBER_GREEN}]", style=MUTED)
    console.print()


def _animation_frame(
    fox_text: str,
    wordmark_text: Optional[str] = None,
    status_lines: Optional[List[Text]] = None,
) -> Group:
    """Compose one in-place animation frame as a single renderable.

    Rendering the whole frame as one Group (rather than a sequence of
    separate console.print calls) is what lets rich.live.Live redraw
    it cleanly in place: Live diffs/replaces this single renderable on
    each update instead of appending new permanent lines.
    """
    parts: List[Text] = [Text(fox_text, style=f"bold {FOX_ORANGE}")]
    if wordmark_text:
        parts.append(Text(""))
        parts.append(Text(wordmark_text, style=f"bold {FOX_ORANGE}"))
    if status_lines:
        parts.append(Text(""))
        parts.extend(status_lines)
    return Group(*parts)


def run_startup(
    console: Console,
    animate: bool = True,
    sleep_fn: SleepFn = time.sleep,
    records_count: int = DEFAULT_SIGNATURE_COUNT,
) -> None:
    """Play the startup animation (if applicable) then show the final banner.

    Args:
        console: Rich console to render to.
        animate: Whether to attempt the animated sequence at all. Even
            when True, the animation is skipped if the console is not
            attached to an interactive terminal (see should_animate).
        sleep_fn: Injected sleep function so tests can run this
            instantly by passing a no-op. Defaults to time.sleep.
        records_count: Number of signatures to report in the final
            banner. The database is loaded once by the caller -- this
            function never reloads it, and never loads it itself.

    Rendering approach:
        The animated stages are rendered through a single rich.live.Live
        region with transient=True. Live redraws that region in place
        (via cursor movement, not full-screen clears or repeated
        prints), and transient=True erases the entire region from the
        terminal the moment the animation finishes -- so no
        intermediate frame is ever left behind in the scrollback.
        Exactly one call to print_final_banner happens after the Live
        region closes, producing a single, permanent, non-duplicated
        banner in the terminal history.
    """
    if not animate or not getattr(console, "is_terminal", False):
        print_final_banner(console, records_count=records_count)
        return

    with Live(console=console, transient=True, auto_refresh=False) as live:
        # Stage 1-3: fox-head logo reveals progressively (ears -> face -> full head).
        for frame in FOX_HEAD_FRAMES:
            live.update(_animation_frame(frame))
            live.refresh()
            sleep_fn(0.15)

        # Stage 4: reveal the block wordmark beneath the completed fox head.
        live.update(_animation_frame(FOX_HEAD, HASHFOX_WORDMARK))
        live.refresh()
        sleep_fn(0.15)

        # Stage 5: quick readiness checks, appended one at a time.
        status_1 = Text.from_markup(
            f"[bold {CYBER_GREEN}]✓[/bold {CYBER_GREEN}] {records_count} signatures loaded"
        )
        live.update(_animation_frame(FOX_HEAD, HASHFOX_WORDMARK, [status_1]))
        live.refresh()
        sleep_fn(0.1)

        status_2 = Text.from_markup(f"[bold {CYBER_GREEN}]✓[/bold {CYBER_GREEN}] Engine READY")
        live.update(_animation_frame(FOX_HEAD, HASHFOX_WORDMARK, [status_1, status_2]))
        live.refresh()
        sleep_fn(0.15)

    # The Live region above is now fully erased (transient=True). Render
    # the final banner exactly once, as ordinary permanent output.
    print_final_banner(console, records_count=records_count)
