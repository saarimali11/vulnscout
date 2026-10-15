# This file does the actual scanning: find the files, parse them, run the rules.

import ast
import sys
from collections.abc import Iterator
from pathlib import Path

from .models import Finding
from .rules import ALL_RULES, Rule

# Folders we never want to scan.
# Scanning .venv would flag thousands of issues in third-party libraries.
IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist"}


def iter_python_files(target: Path) -> Iterator[Path]:
    """Yield every .py file under target (or target itself if it's a file)."""
    # Case 1: the user pointed us at a single file
    if target.is_file():
        if target.suffix == ".py":
            yield target
        return

    # Case 2: it's a folder, so search through it recursively.
    # sorted() makes the output order the same every run.
    for path in sorted(target.rglob("*.py")):
        # path.parts is each piece of the path, e.g. ("src", ".venv", "lib.py").
        # If any piece is an ignored folder, skip the file.
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        yield path


def scan_file(path: Path, rules: list[type[Rule]] | None = None) -> list[Finding]:
    """Run every rule against one file and return all findings."""
    # Use the full rule list unless a specific one was passed in (tests do this)
    rules = ALL_RULES if rules is None else rules

    try:
        # Parse the source code into a syntax tree (ast = abstract syntax tree)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError) as exc:
        # A broken file shouldn't crash the whole scan.
        # Print a warning to stderr (so it doesn't mix with real output) and move on.
        print(f"warning: skipped {path} ({exc.__class__.__name__})", file=sys.stderr)
        return []

    findings: list[Finding] = []
    for rule_cls in rules:
        # Make a fresh rule object for each file so findings don't carry over
        rule = rule_cls(str(path))
        # visit() walks the whole tree and calls the rule's visit_* methods
        rule.visit(tree)
        findings.extend(rule.findings)
    return findings


def scan_path(target: Path, rules: list[type[Rule]] | None = None) -> list[Finding]:
    """Scan a file or folder and return every finding from every file."""
    findings: list[Finding] = []
    for path in iter_python_files(target):
        findings.extend(scan_file(path, rules))
    return findings