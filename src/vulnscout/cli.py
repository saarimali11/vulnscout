# This file is the command-line interface: it reads what the user typed
# and decides what to run and how to print the results.

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .scanner import scan_path


def build_parser() -> argparse.ArgumentParser:
    """Set up which commands and flags the program understands."""
    parser = argparse.ArgumentParser(
        prog="vulnscout",
        description="Static security scanner for Python, mapped to the OWASP Top 10.",
    )
    # Gives us "vulnscout --version" for free
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    # Subcommands let us add more later (like "vulnscout rules").
    # required=True means the user has to pick one.
    sub = parser.add_subparsers(dest="command", required=True)

    # The "scan" subcommand: vulnscout scan <path>
    scan = sub.add_parser("scan", help="scan a file or directory")
    # type=Path converts the typed string into a Path object automatically
    scan.add_argument("path", type=Path)
    # choices= rejects anything except these two values
    scan.add_argument("--format", choices=["text", "json"], default="text")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns an exit code: 0 = clean, 1 = findings, 2 = bad input."""
    # argv=None means "use what was typed in the terminal".
    # Tests pass a list instead so they can call main() directly.
    args = build_parser().parse_args(argv)

    # Validate input before doing any work
    if not args.path.exists():
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2

    findings = scan_path(args.path)

    if args.format == "json":
        # asdict turns each Finding into a plain dictionary so json can handle it.
        # Severity is a str subclass,  so it serializes fine too.
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        # Print in the common "file:line:col" format that editors can click on
        for f in findings:
            print(f"{f.file}:{f.line}:{f.col} [{f.severity.value.upper()}] "
                  f"{f.rule_id} ({f.owasp}) {f.message}")
        print(f"\n{len(findings)} issue(s) found.")

    # Non-zero exit code when issues exist. This is how CI knows to fail the build.
    return 1 if findings else 0