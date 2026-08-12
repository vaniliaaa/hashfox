"""
backend/cli.py

HashFox terminal CLI.

This module is presentation-only: it never reimplements detection,
scoring, or command-preparation logic. It calls exclusively into:

    backend.database.load_database
    backend.analyzer.analyze_hash
    backend.pentest.build_pentest_assistance / select_plausible_targets

HashFox NEVER executes Hashcat, John the Ripper, or any other command.
This CLI only displays/prepares text -- there is no subprocess, no
os.system, no shell execution of generated commands anywhere here.
"""

from __future__ import annotations

import argparse
import shlex
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from rich.console import Console

from backend import __version__, analyzer, banner, database, pentest

# ---------------------------------------------------------------------------
# Presentation-only threshold: which candidates are "prominent enough" to
# print in full in the terminal by default. This mirrors the intent of
# backend.pentest.select_plausible_targets but is purely a CLI display
# concern -- it never changes what the backend considers a candidate.
# ---------------------------------------------------------------------------
CLI_PROMINENT_CANDIDATE_LIMIT = 8


def _get_console() -> Console:
    """Create a fresh Console bound to the current sys.stdout.

    Created fresh per call (rather than at import time) so output
    capture in tests works reliably. Automatic value highlighting is
    disabled so numbers/paths in hashes and commands render as plain
    text instead of being recolored by Rich's default heuristics.
    """
    return Console(highlight=False)


def _get_records() -> List[Dict[str, Any]]:
    """Load the offline database, converting failures into a CLI-friendly error."""
    try:
        return database.load_database()
    except database.DatabaseError as exc:
        console = _get_console()
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise SystemExit(1)


def _print_header(console: Console) -> None:
    console.print("[bold]🦊 HashFox[/bold]")
    console.print("[dim]Smart Hash Intelligence & Pentest Assistant[/dim]")
    console.print()


def _format_value(value: Any) -> str:
    if value is None or value == "":
        return "Unknown"
    return str(value)


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------
def _render_candidates(console: Console, candidates: List[Dict[str, Any]], show_all: bool) -> None:
    console.print("[bold]Possible Matches[/bold]")
    console.print()

    if not candidates:
        console.print("[yellow]No reliable structural match found.[/yellow]")
        console.print(
            "Check whether the value is truncated, whether it may be encoded "
            "rather than hashed, and verify the source/context."
        )
        return

    to_show = candidates if show_all else candidates[:CLI_PROMINENT_CANDIDATE_LIMIT]

    for idx, candidate in enumerate(to_show, start=1):
        name = candidate.get("name", "Unknown")
        confidence = candidate.get("confidence")
        console.print(f"[bold]{idx}. {name}[/bold]")
        console.print(f"   Confidence: {_format_value(confidence)}%")
        console.print(f"   Hashcat Mode: {_format_value(candidate.get('hashcat_mode'))}")
        console.print(f"   John Format: {_format_value(candidate.get('john_format'))}")
        console.print(f"   Security: {_format_value(candidate.get('security_level'))}")
        console.print()

    remaining = len(candidates) - len(to_show)
    if remaining > 0:
        console.print(
            f"[dim]…and {remaining} weaker candidate(s) not shown. "
            "Use --all to display every candidate.[/dim]"
        )
        console.print()


def _render_ambiguity(console: Console, result: Dict[str, Any]) -> None:
    if result.get("ambiguous"):
        console.print("[bold yellow]⚠ Ambiguous structure[/bold yellow]")
        console.print()
        message = result.get("ambiguity_message") or (
            "Multiple formats share the same structural signature. "
            "Verify source/context before selecting a cracking mode."
        )
        console.print(message)
        console.print()


def _render_pentest_assistance(console: Console, assistance: Dict[str, Any]) -> None:
    if assistance.get("ambiguous") and assistance.get("warning"):
        console.print(f"[bold yellow]⚠ {assistance['warning']}[/bold yellow]")
        console.print()

    console.print("[dim]Prepared commands — review before running. HashFox never executes anything.[/dim]")
    console.print()

    targets = assistance.get("targets") or []
    if not targets:
        console.print("[yellow]No plausible targets available for command preparation.[/yellow]")
        console.print()

    for target in targets:
        console.print(f"[bold]{target.get('name', 'Unknown')}[/bold] "
                      f"({_format_value(target.get('confidence'))}% confidence)")
        console.print()

        console.print("[bold]HASHCAT[/bold]")
        console.print()
        hashcat = target.get("hashcat_commands") or {}
        if hashcat.get("dictionary"):
            console.print(hashcat["dictionary"])
        if hashcat.get("rules"):
            console.print(hashcat["rules"])
        if hashcat.get("mask"):
            console.print(hashcat["mask"])
        if not any(hashcat.values()):
            console.print("[dim]No verified Hashcat mode is available for this candidate.[/dim]")
        console.print()

        console.print("[bold]JOHN THE RIPPER[/bold]")
        console.print()
        if target.get("john_command"):
            console.print(target["john_command"])
        else:
            console.print(
                target.get("john_command_unavailable_reason")
                or "Verified John the Ripper format unavailable."
            )
        console.print()

        console.print(f"Security level: {_format_value(target.get('security_level'))}")
        recommended_attacks = target.get("recommended_attacks") or []
        if recommended_attacks:
            console.print(f"Recommended attacks: {', '.join(recommended_attacks)}")
        recommended_wordlists = target.get("recommended_wordlists") or []
        if recommended_wordlists:
            console.print(f"Recommended wordlists: {', '.join(recommended_wordlists)}")
        console.print()
        console.print("─" * 40)
        console.print()

    next_steps = assistance.get("next_steps") or []
    if next_steps:
        console.print("[bold]Next steps[/bold]")
        for i, step in enumerate(next_steps, start=1):
            console.print(f"  {i}. {step}")
        console.print()

    fox_tip = assistance.get("fox_tip")
    if fox_tip:
        console.print(f"[bold]🦊 Fox Tip[/bold] {fox_tip}")
        console.print()


def cmd_analyze(args: argparse.Namespace) -> int:
    console = _get_console()
    value = args.hash

    if value is None or not value.strip():
        console.print("[bold red]Error:[/bold red] hash must not be empty.")
        return 1

    records = _get_records()
    result = analyzer.analyze_hash(value, records)

    _print_header(console)
    console.print("[bold]Input:[/bold]")
    console.print(value)
    console.print()

    _render_candidates(console, result["candidates"], show_all=args.all)
    _render_ambiguity(console, result)

    if args.pentest:
        assistance = pentest.build_pentest_assistance(
            result,
            hash_file=args.hash_file,
            wordlist=args.wordlist,
            rules_file=args.rules,
            mask=args.mask,
        )
        _render_pentest_assistance(console, assistance)

    return 0


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------
def cmd_scan(args: argparse.Namespace) -> int:
    console = _get_console()
    path = Path(args.file)

    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {args.file}")
        return 1
    if not path.is_file():
        console.print(f"[bold red]Error:[/bold red] Not a file: {args.file}")
        return 1

    try:
        raw_text = path.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        console.print(f"[bold red]Error:[/bold red] Permission denied: {args.file}")
        return 1
    except OSError as exc:
        console.print(f"[bold red]Error:[/bold red] Could not read {args.file}: {exc}")
        return 1

    records = _get_records()

    console.print("[bold]HashFox Scan[/bold]")
    console.print(f"File: {args.file}")
    console.print()

    analyzed = 0
    ambiguous_count = 0
    no_match_count = 0

    for line_no, raw_line in enumerate(raw_text.splitlines(), start=1):
        value = raw_line.strip()
        if not value:
            continue

        analyzed += 1
        result = analyzer.analyze_hash(value, records)
        candidates = result["candidates"]

        console.print(f"[bold][{line_no}][/bold]")
        console.print(_truncate_for_display(value))

        if not candidates:
            console.print("[yellow]No match[/yellow]")
            no_match_count += 1
        else:
            prominent = pentest.select_plausible_targets(candidates)
            names = " / ".join(c.get("name", "Unknown") for c in prominent)
            top_confidence = prominent[0].get("confidence") if prominent else None
            console.print(names)
            console.print(f"{_format_value(top_confidence)}%")
            if result["ambiguous"]:
                console.print("[yellow]AMBIGUOUS[/yellow]")
                ambiguous_count += 1

        if args.pentest:
            assistance = pentest.build_pentest_assistance(
                result,
                hash_file=args.hash_file,
                wordlist=args.wordlist,
                rules_file=args.rules,
                mask=args.mask,
            )
            console.print()
            _render_pentest_assistance(console, assistance)

        console.print()

    console.print("[bold]Summary:[/bold]")
    console.print(f"Analyzed: {analyzed}")
    console.print(f"Ambiguous: {ambiguous_count}")
    console.print(f"No match: {no_match_count}")

    return 0


def _truncate_for_display(value: str, limit: int = 80) -> str:
    if len(value) <= limit:
        return value
    return value[: limit // 2] + "…" + value[-(limit // 2):]


# ---------------------------------------------------------------------------
# lookup
# ---------------------------------------------------------------------------
def _normalize_lookup_text(value: str) -> str:
    return "".join(ch for ch in value.lower() if ch.isalnum())


def _matches_lookup(record: Dict[str, Any], normalized_query: str) -> bool:
    fields = [record.get("name") or ""]
    fields.extend(record.get("aliases") or [])
    fields.extend(record.get("variants") or [])
    for field in fields:
        normalized_field = _normalize_lookup_text(str(field))
        if not normalized_field:
            continue
        if normalized_query in normalized_field or normalized_field in normalized_query:
            return True
    return False


def _render_lookup_record(console: Console, record: Dict[str, Any]) -> None:
    console.print(f"[bold]{record.get('name', 'Unknown')}[/bold]")
    console.print()
    console.print(f"Category: {_format_value(record.get('category'))}")
    console.print(f"Hashcat Mode: {_format_value(record.get('hashcat_mode'))}")
    console.print(f"John Format: {_format_value(record.get('john_format'))}")
    console.print(f"Detection Quality: {_format_value(record.get('detection_quality'))}")
    console.print(f"Security Level: {_format_value(record.get('security_level'))}")
    console.print(f"Length: {_format_value(record.get('length'))}")
    console.print(f"Charset: {_format_value(record.get('character_set'))}")
    console.print()

    description = record.get("description")
    if description:
        console.print("Description:")
        console.print(description)
        console.print()

    aliases = record.get("aliases") or []
    if aliases:
        console.print("Aliases:")
        console.print(", ".join(aliases))
        console.print()


def cmd_lookup(args: argparse.Namespace) -> int:
    console = _get_console()
    query = (args.query or "").strip()

    if not query:
        console.print("[bold red]Error:[/bold red] lookup query must not be empty.")
        return 1

    records = _get_records()
    normalized_query = _normalize_lookup_text(query)
    matches = [r for r in records if _matches_lookup(r, normalized_query)]

    if not matches:
        console.print("No matching formats found.")
        return 1

    for i, record in enumerate(matches):
        _render_lookup_record(console, record)
        if i < len(matches) - 1:
            console.print("─" * 40)
            console.print()

    return 0


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------
def cmd_serve(args: argparse.Namespace) -> int:
    console = _get_console()
    try:
        import uvicorn
    except ImportError:
        console.print(
            "[bold red]Error:[/bold red] uvicorn is required to run 'hashfox serve'. "
            "Install it with: pip install uvicorn"
        )
        return 1

    console.print(f"[bold]🦊 HashFox[/bold] starting at http://{args.host}:{args.port}")
    uvicorn.run("backend.app:app", host=args.host, port=args.port, reload=args.reload)
    return 0


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def _add_pentest_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--hash-file",
        dest="hash_file",
        default=pentest.DEFAULT_HASH_FILE,
        help=f"Hash file referenced in generated commands (default: {pentest.DEFAULT_HASH_FILE})",
    )
    parser.add_argument(
        "--wordlist",
        dest="wordlist",
        default=pentest.DEFAULT_WORDLIST,
        help=f"Wordlist referenced in generated commands (default: {pentest.DEFAULT_WORDLIST})",
    )
    parser.add_argument(
        "--rules",
        dest="rules",
        default=None,
        help="Optional Hashcat rules file for the rule-based command.",
    )
    parser.add_argument(
        "--mask",
        dest="mask",
        default=None,
        help="Optional Hashcat mask for the mask-attack command (e.g. ?d?d?d?d).",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the HashFox CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="hashfox",
        description="🦊 HashFox — Smart Hash Intelligence & Pentest Assistant (offline).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"HashFox {__version__}",
    )
    parser.add_argument(
        "--no-banner",
        dest="no_banner",
        action="store_true",
        help="Skip the startup animation and enter interactive mode immediately.",
    )

    subparsers = parser.add_subparsers(dest="command")

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a single hash.")
    analyze_parser.add_argument("hash", help="The hash / encoded credential string to analyze.")
    analyze_parser.add_argument(
        "--pentest", action="store_true", help="Also prepare Hashcat/John command guidance."
    )
    analyze_parser.add_argument(
        "--all", action="store_true", help="Show every candidate instead of just the prominent ones."
    )
    _add_pentest_options(analyze_parser)
    analyze_parser.set_defaults(func=cmd_analyze)

    scan_parser = subparsers.add_parser("scan", help="Analyze every hash in a text file.")
    scan_parser.add_argument("file", help="Path to a text file, one hash per line.")
    scan_parser.add_argument(
        "--pentest", action="store_true", help="Also prepare Hashcat/John command guidance per entry."
    )
    _add_pentest_options(scan_parser)
    scan_parser.set_defaults(func=cmd_scan)

    lookup_parser = subparsers.add_parser("lookup", help="Look up a format in the offline database.")
    lookup_parser.add_argument("query", help="Format name, alias, or variant to search for.")
    lookup_parser.set_defaults(func=cmd_lookup)

    serve_parser = subparsers.add_parser("serve", help="Launch the HashFox web application.")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1).")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000).")
    serve_parser.add_argument(
        "--reload", action="store_true", help="Enable auto-reload (development only, off by default)."
    )
    serve_parser.set_defaults(func=cmd_serve)

    return parser


# ---------------------------------------------------------------------------
# Interactive console
# ---------------------------------------------------------------------------
_INTERACTIVE_SUBCOMMANDS = ("analyze", "scan", "lookup", "serve")


def _print_interactive_help(console: Console) -> None:
    console.print("[bold]Available commands[/bold]")
    console.print()
    console.print("  analyze HASH [--pentest] [--hash-file F] [--wordlist W] [--rules R] [--mask M]")
    console.print("  scan FILE [--pentest] [--hash-file F] [--wordlist W] [--rules R] [--mask M]")
    console.print("  lookup QUERY")
    console.print("  serve [--host H] [--port P] [--reload]")
    console.print("  help")
    console.print("  banner")
    console.print("  clear")
    console.print("  version")
    console.print("  exit / quit")
    console.print()


def _run_interactive_line(console: Console, parser: argparse.ArgumentParser, records: List[Dict[str, Any]], line: str) -> bool:
    """Handle one interactive console line. Returns False to end the loop."""
    stripped = line.strip()
    if not stripped:
        return True

    lowered = stripped.lower()

    if lowered in ("exit", "quit"):
        console.print("[dim]Goodbye.[/dim]")
        return False
    if lowered == "help":
        _print_interactive_help(console)
        return True
    if lowered == "version":
        console.print(f"HashFox {__version__}")
        return True
    if lowered == "banner":
        banner.print_final_banner(console, records_count=len(records))
        return True
    if lowered == "clear":
        console.clear()
        return True

    try:
        tokens = shlex.split(stripped)
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return True

    if not tokens:
        return True

    if tokens[0] not in _INTERACTIVE_SUBCOMMANDS:
        console.print(
            f"[bold red]Unknown command:[/bold red] {tokens[0]!r}. "
            "Type 'help' for available commands."
        )
        return True

    try:
        parsed_args = parser.parse_args(tokens)
    except SystemExit:
        # argparse already printed its own usage/error message.
        return True

    if not getattr(parsed_args, "command", None):
        return True

    try:
        parsed_args.func(parsed_args)
    except SystemExit:
        pass
    except Exception as exc:  # noqa: BLE001 - keep the console alive on errors
        console.print(f"[bold red]Unexpected error:[/bold red] {exc}")

    return True


def cmd_interactive(args: argparse.Namespace, input_fn: Optional[Callable[[str], str]] = None) -> int:
    """Launch the interactive HashFox console (bare `hashfox` invocation)."""
    if input_fn is None:
        input_fn = input  # resolved at call time so tests can monkeypatch builtins.input

    console = _get_console()
    records = _get_records()

    no_banner = bool(getattr(args, "no_banner", False))
    animate = banner.should_animate(console, no_banner)
    banner.run_startup(console, animate=animate, sleep_fn=time.sleep, records_count=len(records))

    console.print("[dim]Type 'help' for a list of commands, or 'exit' to quit.[/dim]")
    console.print()

    parser = build_parser()

    while True:
        try:
            line = input_fn("hashfox ❯ ")
        except (EOFError, KeyboardInterrupt, OSError):
            console.print()
            return 0

        if not _run_interactive_line(console, parser, records, line):
            return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    """HashFox CLI entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        return cmd_interactive(args)

    try:
        return args.func(args)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001 - CLI top-level safety net
        console = _get_console()
        console.print(f"[bold red]Unexpected error:[/bold red] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
