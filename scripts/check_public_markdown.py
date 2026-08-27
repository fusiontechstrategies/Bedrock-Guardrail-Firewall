#!/usr/bin/env python3
"""Reject typography and command-path regressions in public Markdown."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BAD_WINDOWS_VENV = re.compile(r"(?<!\.)\\\.venv")


def public_markdown_files() -> list[Path]:
    files = set(ROOT.glob("*.md"))
    for directory in (ROOT / "docs", ROOT / ".github"):
        if directory.is_dir():
            files.update(directory.rglob("*.md"))
    return sorted(files)


def main() -> int:
    problems: list[str] = []
    files = public_markdown_files()
    for path in files:
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if "\u2014" in line:
                problems.append(f"{path.relative_to(ROOT)}:{line_number}: em dash")
            if BAD_WINDOWS_VENV.search(line):
                problems.append(
                    f"{path.relative_to(ROOT)}:{line_number}: PowerShell path must "
                    "start with .\\.venv"
                )
    if problems:
        print("\n".join(problems))
        return 1
    print(f"Public Markdown check passed for {len(files)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
