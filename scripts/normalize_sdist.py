#!/usr/bin/env python3
"""Normalize a gzip-compressed source distribution for reproducible builds."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import re
import tarfile
import tempfile
import unicodedata
from io import BytesIO
from pathlib import Path


class SdistNormalizationError(RuntimeError):
    """A source distribution cannot be normalized safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SdistNormalizationError(message)


def validate_member_name(name: str) -> None:
    require("\\" not in name, f"Archive member uses a backslash: {name!r}")
    require(not name.startswith("/"), f"Archive member is absolute: {name!r}")
    require(
        re.match(r"^[A-Za-z]:", name) is None,
        f"Archive member uses a drive path: {name!r}",
    )
    parts = name.rstrip("/").split("/")
    require(
        bool(parts) and all(part not in {"", ".", ".."} for part in parts),
        f"Archive member traverses or aliases a path: {name!r}",
    )


def content_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_members(path: Path) -> list[tuple[tarfile.TarInfo, bytes | None]]:
    members: list[tuple[tarfile.TarInfo, bytes | None]] = []
    names: set[str] = set()
    portable_names: set[str] = set()
    with tarfile.open(path, mode="r:gz") as archive:
        for member in archive.getmembers():
            validate_member_name(member.name)
            name = member.name.rstrip("/")
            require(name not in names, f"Archive contains a duplicate member: {name!r}")
            names.add(name)
            portable_name = unicodedata.normalize("NFC", name).casefold()
            require(
                portable_name not in portable_names,
                f"Archive contains a non-portable duplicate member: {name!r}",
            )
            portable_names.add(portable_name)
            require(
                member.isfile() or member.isdir(),
                f"Archive contains a link or device: {member.name!r}",
            )
            value = None
            if member.isfile():
                handle = archive.extractfile(member)
                require(handle is not None, f"Unable to read archive member: {name!r}")
                value = handle.read()
                require(
                    len(value) == member.size, f"Archive member is truncated: {name!r}"
                )
            members.append((member, value))
    return members


def member_identity(
    members: list[tuple[tarfile.TarInfo, bytes | None]],
) -> list[tuple[str, str, int]]:
    return [
        (
            member.name.rstrip("/"),
            "directory" if member.isdir() else content_digest(value or b""),
            0 if value is None else len(value),
        )
        for member, value in members
    ]


def normalize_sdist(path: Path, source_date_epoch: int) -> str:
    require(not path.is_symlink(), "Source distribution must not be a symbolic link")
    path = path.resolve(strict=True)
    require(path.is_file(), "Source distribution is invalid")
    require(path.name.endswith(".tar.gz"), "Source distribution must end in .tar.gz")
    require(source_date_epoch >= 0, "SOURCE_DATE_EPOCH must not be negative")
    require(
        source_date_epoch <= 0xFFFFFFFF,
        "SOURCE_DATE_EPOCH exceeds the gzip timestamp range",
    )
    members = read_members(path)
    original_identity = member_identity(members)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    os.close(descriptor)
    temporary_path = Path(temporary_name)
    try:
        with (
            temporary_path.open("wb") as raw_output,
            gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=raw_output,
                mtime=source_date_epoch,
            ) as gzip_output,
            tarfile.open(
                fileobj=gzip_output,
                mode="w|",
                format=tarfile.PAX_FORMAT,
            ) as output,
        ):
            for original, value in sorted(members, key=lambda item: item[0].name):
                normalized = tarfile.TarInfo(original.name.rstrip("/"))
                normalized.mtime = source_date_epoch
                normalized.uid = 0
                normalized.gid = 0
                normalized.uname = ""
                normalized.gname = ""
                normalized.pax_headers = {}
                if original.isdir():
                    normalized.type = tarfile.DIRTYPE
                    normalized.mode = 0o755
                    normalized.size = 0
                    output.addfile(normalized)
                else:
                    require(value is not None, "Regular archive member has no data")
                    normalized.type = tarfile.REGTYPE
                    normalized.mode = 0o755 if original.mode & 0o111 else 0o644
                    normalized.size = len(value)
                    output.addfile(normalized, BytesIO(value))
        normalized_members = read_members(temporary_path)
        require(
            member_identity(normalized_members) == sorted(original_identity),
            "Normalized archive changed names or file contents",
        )
        temporary_path.replace(path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    arguments = parser.parse_args()
    digest = normalize_sdist(arguments.path, arguments.source_date_epoch)
    print(f"Normalized {arguments.path.name}: sha256:{digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
