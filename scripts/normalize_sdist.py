#!/usr/bin/env python3
"""Normalize a gzip-compressed source distribution for reproducible builds."""

from __future__ import annotations

import argparse
import contextlib
import gzip
import hashlib
import importlib.util
import os
import re
import tarfile
import tempfile
import unicodedata
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "trusted_archive_limits", Path(__file__).resolve().with_name("archive_limits.py")
)
if _spec is None or _spec.loader is None:
    raise RuntimeError("Missing archive limits helper")
limits = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(limits)


class SdistNormalizationError(RuntimeError):
    """A source distribution cannot be normalized safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SdistNormalizationError(message)


def validate_member_name(name: str) -> None:
    require(
        ":" not in name,
        f"Archive member contains a drive path or Windows stream alias: {name!r}",
    )
    require("\\" not in name, f"Archive member uses a backslash: {name!r}")
    require(not name.startswith("/"), f"Archive member is absolute: {name!r}")
    require(
        re.match(r"^[A-Za-z]:", name) is None,
        f"Archive member uses a drive path: {name!r}",
    )
    parts = name.rstrip("/").split("/")
    require(
        all(re.search(r"~[0-9]", part) is None for part in parts),
        f"Archive member contains a Windows short-name alias: {name!r}",
    )
    require(
        bool(parts) and all(part not in {"", ".", ".."} for part in parts),
        f"Archive member traverses or aliases a path: {name!r}",
    )


def content_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@contextlib.contextmanager
def read_members(path: Path):
    """Retain bounded metadata and content digests, with bodies in a disk spool."""
    try:
        compressed = limits.regular_snapshot(path)
        with limits.bounded_tar_stream(compressed) as stream:
            members = []
            names, portable_names = set(), set()
            total = 0
            with tarfile.open(fileobj=stream, mode="r:") as archive:
                for member in archive:
                    require(
                        len(members) < limits.MAX_MEMBERS,
                        "Archive member count budget exceeded",
                    )
                    require(
                        0 <= member.size <= limits.MAX_MEMBER_BYTES,
                        "Archive member byte budget exceeded",
                    )
                    total += member.size
                    require(
                        total <= limits.MAX_TOTAL_BYTES,
                        "Archive total byte budget exceeded",
                    )
                    validate_member_name(member.name)
                    name = member.name.rstrip("/")
                    require(
                        name not in names,
                        f"Archive contains a duplicate member: {name!r}",
                    )
                    names.add(name)
                    portable = unicodedata.normalize("NFC", name).casefold()
                    require(
                        portable not in portable_names,
                        f"Archive contains a non-portable duplicate member: {name!r}",
                    )
                    portable_names.add(portable)
                    require(
                        member.isfile() or member.isdir(),
                        f"Archive contains a link or device: {name!r}",
                    )
                    digest = hashlib.sha256()
                    if member.isfile():
                        handle = archive.extractfile(member)
                        require(handle is not None, "Unable to read archive member")
                        with handle:
                            remaining = member.size
                            while remaining:
                                block = handle.read(min(remaining, limits.CHUNK_BYTES))
                                require(
                                    bool(block),
                                    f"Archive member is truncated: {name!r}",
                                )
                                digest.update(block)
                                remaining -= len(block)
                            require(
                                not handle.read(1),
                                "Archive member exceeds declared size",
                            )
                    members.append((member, digest.hexdigest()))
            yield stream, members
    except limits.ArchiveLimitError as exc:
        raise SdistNormalizationError(str(exc)) from exc


def member_identity(members):
    return [
        (
            member.name.rstrip("/"),
            "directory" if member.isdir() else digest,
            member.size,
        )
        for member, digest in members
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
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    os.close(descriptor)
    temporary_path = Path(temporary_name)
    try:
        with read_members(path) as (source_stream, members):
            original_identity = member_identity(members)
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
                for original, _ in sorted(members, key=lambda item: item[0].name):
                    normalized = tarfile.TarInfo(original.name.rstrip("/"))
                    normalized.mtime = 0
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
                        normalized.type = tarfile.REGTYPE
                        normalized.mode = 0o755 if original.mode & 0o111 else 0o644
                        normalized.size = original.size
                        source_stream.seek(original.offset_data)
                        output.addfile(normalized, source_stream)
        with read_members(temporary_path) as (_, normalized_members):
            require(
                member_identity(normalized_members) == sorted(original_identity),
                "Normalized archive changed names or file contents",
            )
        temporary_path.replace(path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
    digest = hashlib.sha256(limits.regular_snapshot(path)).hexdigest()
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
