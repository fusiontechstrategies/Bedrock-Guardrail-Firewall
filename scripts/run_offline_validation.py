#!/usr/bin/env python3
"""Run offline CLI suites in a private temporary state namespace."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path


def main() -> int:
    source = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(source))
    try:
        from orchestrator import main as runtime_main
    finally:
        sys.path.pop(0)
    # CI checkouts can grant mutation rights to other ordinary principals.
    # Use the same private temporary ancestry exercised by the unit tests.
    with tempfile.TemporaryDirectory(prefix="bedrock-offline-ci-") as directory:
        state = Path(directory) / "state"
        for command in ("self-test", "red-team"):
            result = runtime_main(
                ["--data-dir", str(state), "--presidio-mode", "disabled", command]
            )
            if result:
                return result
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
