"""Verify immutable source, asset bytes, and remote release tag identity."""

from __future__ import annotations

import argparse
import hashlib
import json
import re

# Only Git/GitHub identity queries use argument arrays without a shell.
import subprocess  # nosec B404
from pathlib import Path


def command(arguments, cwd=None):
    if arguments[0] not in {"git", "gh"}:
        raise ValueError("Only Git and GitHub identity queries are allowed")
    # The executable is validated above; query arguments remain separate.
    return subprocess.run(arguments, cwd=cwd, check=True, capture_output=True).stdout  # noqa: S603 # nosec B603


def verify_source(root, commit, files):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Invalid source commit")
    for name in files:
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Unsafe source file: {name}")
        expected = command(["git", "show", f"{commit}:{name}"], cwd=root)
        if path.read_bytes() != expected:
            raise ValueError(f"Source differs from verified commit: {name}")


def manifest(directory):
    if not directory.is_dir():
        raise ValueError("Missing asset directory")
    result = {}
    for path in directory.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError("Asset directory contains a non-regular entry")
        result[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    if len(result) != 5:
        raise ValueError("Release must contain exactly five assets")
    return result


def verify_assets(directory, expected):
    if manifest(directory) != expected:
        raise ValueError("Release asset bytes differ from the final verified manifest")


def verify_distributions(directory, expected):
    selected = {
        name: digest
        for name, digest in expected.items()
        if name.endswith((".whl", ".tar.gz"))
    }
    if len(selected) != 2 or {path.name for path in directory.iterdir()} != set(
        selected
    ):
        raise ValueError(
            "Publication must contain exactly the two verified distributions"
        )
    for name, digest in selected.items():
        path = directory / name
        if (
            path.is_symlink()
            or not path.is_file()
            or hashlib.sha256(path.read_bytes()).hexdigest() != digest
        ):
            raise ValueError(
                "Publication distribution differs from the attested original"
            )


def verify_tag(repository, tag, commit):
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("Invalid release tag")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid repository")
    ref = json.loads(command(["gh", "api", f"repos/{repository}/git/ref/tags/{tag}"]))[
        "object"
    ]
    for _ in range(10):
        if ref["type"] == "commit":
            if ref["sha"] != commit:
                raise ValueError(
                    "Remote release tag no longer points to the verified commit"
                )
            return
        if ref["type"] != "tag":
            break
        ref = json.loads(
            command(["gh", "api", f"repos/{repository}/git/tags/{ref['sha']}"])
        )["object"]
    raise ValueError("Release tag cannot be peeled to a commit")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    assets = commands.add_parser("assets")
    assets.add_argument("directory", type=Path)
    assets.add_argument("expected")
    distributions = commands.add_parser("distributions")
    distributions.add_argument("directory", type=Path)
    distributions.add_argument("expected")
    remote = commands.add_parser("tag")
    remote.add_argument("repository")
    remote.add_argument("tag")
    remote.add_argument("commit")
    args = parser.parse_args()
    if args.operation == "distributions":
        verify_distributions(args.directory, json.loads(args.expected))
    elif args.operation == "assets":
        if args.expected == "-":
            print(
                json.dumps(
                    manifest(args.directory), sort_keys=True, separators=(",", ":")
                )
            )
        else:
            verify_assets(args.directory, json.loads(args.expected))
    else:
        verify_tag(args.repository, args.tag, args.commit)


if __name__ == "__main__":
    main()
