#!/usr/bin/env python3
"""Validate release distributions and write deterministic integrity evidence."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import re
import stat
import tarfile
import unicodedata
import zipfile
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
PROJECT_NAME = "bedrock-guardrail-firewall"
ARCHIVE_NAME = "bedrock_guardrail_firewall"
STABLE_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
COMMIT_ID = re.compile(r"^[0-9a-f]{40}$")
CHANGELOG_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


class ReleaseEvidenceError(RuntimeError):
    """A release artifact or source identity failed validation."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseEvidenceError(message)


def read_project_version(source_root: Path) -> str:
    section = ""
    versions: list[str] = []
    for raw_line in (
        (source_root / "pyproject.toml").read_text(encoding="utf-8").splitlines()
    ):
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line
            continue
        if section == "[project]":
            match = re.fullmatch(r'version\s*=\s*"([^"]+)"', line)
            if match:
                versions.append(match.group(1))
    require(len(versions) == 1, "pyproject.toml must define one project version")
    return versions[0]


def read_constant(path: Path, name: str) -> str:
    pattern = re.compile(rf'(?m)^{re.escape(name)}\s*=\s*"([^"]+)"\s*$')
    matches = pattern.findall(path.read_text(encoding="utf-8"))
    require(len(matches) == 1, f"{path.name} must define one {name} constant")
    return matches[0]


def validate_source_identity(source_root: Path, tag: str) -> str:
    version = read_project_version(source_root)
    require(
        STABLE_VERSION.fullmatch(version) is not None,
        f"Release version must be stable X.Y.Z, not {version!r}",
    )
    require(tag == f"v{version}", f"Release tag {tag!r} does not match v{version}")
    runtime_version = read_constant(source_root / "orchestrator.py", "__version__")
    validator_version = read_constant(
        source_root / "scripts" / "validate_installed_package.py",
        "EXPECTED_VERSION",
    )
    require(runtime_version == version, "Runtime and project versions differ")
    require(
        validator_version == version, "Package validator and project versions differ"
    )

    changelog = (source_root / "CHANGELOG.md").read_text(encoding="utf-8")
    header = re.compile(
        rf"(?m)^## \[{re.escape(version)}\] - {CHANGELOG_DATE.pattern}$"
    )
    require(header.search(changelog) is not None, "Changelog release header is missing")
    link = re.compile(
        rf"(?m)^\[{re.escape(version)}\]: https://github\.com/"
        rf"fusiontechstrategies/Bedrock-Guardrail-Firewall/compare/.+\.\.\.v"
        rf"{re.escape(version)}$"
    )
    require(link.search(changelog) is not None, "Changelog release link is missing")
    return version


def archive_parts(name: str) -> tuple[str, ...]:
    require("\\" not in name, f"Archive member uses a backslash: {name!r}")
    require(not name.startswith("/"), f"Archive member is absolute: {name!r}")
    require(
        re.match(r"^[A-Za-z]:", name) is None,
        f"Archive member uses a drive path: {name!r}",
    )
    stripped = name.rstrip("/")
    require(bool(stripped), "Archive contains an empty member name")
    raw_parts = tuple(stripped.split("/"))
    require(
        all(part not in {"", ".", ".."} for part in raw_parts),
        f"Archive member traverses or aliases a path: {name!r}",
    )
    for part in raw_parts:
        require(
            not part.endswith((" ", ".")),
            f"Archive member is not portable across filesystems: {name!r}",
        )
        require(
            all(ord(character) >= 32 and ord(character) != 127 for character in part),
            f"Archive member contains a control character: {name!r}",
        )
        device_name = part.split(".", 1)[0].upper()
        require(
            device_name not in WINDOWS_RESERVED_NAMES,
            f"Archive member uses a reserved Windows name: {name!r}",
        )
    normalized = PurePosixPath(*raw_parts)
    require(
        tuple(normalized.parts) == raw_parts,
        f"Archive member is not a canonical relative path: {name!r}",
    )
    return raw_parts


def validate_public_member(name: str) -> tuple[str, ...]:
    parts = archive_parts(name)
    lowered = tuple(part.lower() for part in parts)
    forbidden_parts = {".git", ".guardrail-data", "__pycache__"}
    require(
        forbidden_parts.isdisjoint(lowered),
        f"Archive contains private or generated state: {name!r}",
    )
    filename = lowered[-1]
    require(
        not filename.endswith((".pyc", ".pyo", ".pfx", ".p12", ".pem")),
        f"Archive contains a prohibited file type: {name!r}",
    )
    require(
        filename != "privacy.key" and not filename.startswith(".env"),
        f"Archive contains a credential or runtime-state filename: {name!r}",
    )
    return parts


def parse_metadata(value: bytes, source: str):
    document = BytesParser(policy=policy.default).parsebytes(value)

    def one(name: str) -> str:
        values = document.get_all(name) or []
        require(len(values) == 1, f"{source} must define one {name} field")
        return str(values[0])

    require(one("Name") == PROJECT_NAME, f"Unexpected name in {source}")
    require(bool(one("Version")), f"Version is missing from {source}")
    require(
        one("Requires-Python") == ">=3.10",
        f"Unexpected Python requirement in {source}",
    )
    require(
        one("License-Expression") == "Apache-2.0",
        f"Unexpected license expression in {source}",
    )
    require(
        one("Description-Content-Type") == "text/markdown",
        f"Unexpected README content type in {source}",
    )
    return document


def validate_wheel(path: Path, version: str) -> None:
    metadata_values: list[bytes] = []
    record_values: list[tuple[str, bytes]] = []
    required_members = {
        "bedrock_guardrail_firewall/__init__.py",
        "bedrock_guardrail_firewall/orchestrator.py",
        "bedrock_guardrail_firewall/guardrail_policy.json",
        "bedrock_guardrail_firewall/guardrail_policy_profiles.json",
        "bedrock_guardrail_firewall/py.typed",
    }
    with zipfile.ZipFile(path) as archive:
        names: set[str] = set()
        portable_names: set[str] = set()
        file_values: dict[str, bytes] = {}
        for member in archive.infolist():
            validate_public_member(member.filename)
            name = member.filename.rstrip("/")
            require(name not in names, f"Wheel contains a duplicate member: {name!r}")
            names.add(name)
            portable_name = unicodedata.normalize("NFC", name).casefold()
            require(
                portable_name not in portable_names,
                f"Wheel contains a non-portable duplicate member: {name!r}",
            )
            portable_names.add(portable_name)
            mode = member.external_attr >> 16
            require(
                not stat.S_ISLNK(mode),
                f"Wheel contains a symbolic link: {member.filename!r}",
            )
            require(
                member.flag_bits & 1 == 0,
                f"Wheel contains an encrypted member: {member.filename!r}",
            )
            if member.is_dir():
                continue
            value = archive.read(member)
            file_values[name] = value
            if member.filename.endswith(".dist-info/METADATA"):
                metadata_values.append(value)
            if member.filename.endswith(".dist-info/RECORD"):
                record_values.append((name, value))
    require(
        required_members.issubset(file_values),
        "Wheel is missing required package files",
    )
    require(len(metadata_values) == 1, "Wheel must contain exactly one METADATA file")
    require(len(record_values) == 1, "Wheel must contain exactly one RECORD file")
    metadata = parse_metadata(metadata_values[0], path.name)
    require(metadata["Version"] == version, "Wheel metadata version mismatch")

    record_name, record_value = record_values[0]
    record_rows: dict[str, tuple[str, str]] = {}
    try:
        rows = csv.reader(io.StringIO(record_value.decode("utf-8"), newline=""))
        for row in rows:
            require(len(row) == 3, "Wheel RECORD contains a malformed row")
            recorded_name, recorded_hash, recorded_size = row
            validate_public_member(recorded_name)
            require(
                recorded_name not in record_rows,
                f"Wheel RECORD contains a duplicate path: {recorded_name!r}",
            )
            record_rows[recorded_name] = (recorded_hash, recorded_size)
    except UnicodeDecodeError as error:
        raise ReleaseEvidenceError("Wheel RECORD is not UTF-8") from error
    require(
        set(record_rows) == set(file_values),
        "Wheel RECORD does not cover the exact archive file set",
    )
    for recorded_name, (recorded_hash, recorded_size) in record_rows.items():
        if recorded_name == record_name:
            require(
                recorded_hash == "" and recorded_size == "",
                "Wheel RECORD must leave its own hash and size empty",
            )
            continue
        value = file_values[recorded_name]
        encoded_hash = base64.urlsafe_b64encode(hashlib.sha256(value).digest())
        expected_hash = "sha256=" + encoded_hash.rstrip(b"=").decode("ascii")
        require(
            recorded_hash == expected_hash,
            f"Wheel RECORD hash mismatch: {recorded_name!r}",
        )
        require(
            recorded_size == str(len(value)),
            f"Wheel RECORD size mismatch: {recorded_name!r}",
        )


def validate_sdist(path: Path, version: str) -> None:
    expected_root = f"{ARCHIVE_NAME}-{version}"
    metadata_values: list[bytes] = []
    names: set[str] = set()
    with tarfile.open(path, mode="r:gz") as archive:
        portable_names: set[str] = set()
        for member in archive.getmembers():
            parts = validate_public_member(member.name)
            name = member.name.rstrip("/")
            require(
                name not in names,
                f"Source distribution contains a duplicate member: {name!r}",
            )
            names.add(name)
            portable_name = unicodedata.normalize("NFC", name).casefold()
            require(
                portable_name not in portable_names,
                "Source distribution contains a non-portable duplicate member: "
                f"{name!r}",
            )
            portable_names.add(portable_name)
            require(
                parts[0] == expected_root,
                f"Source distribution has an unexpected root: {member.name!r}",
            )
            require(
                member.isfile() or member.isdir(),
                f"Source distribution contains a link or device: {member.name!r}",
            )
            if len(parts) == 2 and parts[-1] == "PKG-INFO":
                handle = archive.extractfile(member)
                require(handle is not None, "Unable to read source PKG-INFO")
                metadata_values.append(handle.read())
    require(
        len(metadata_values) == 1,
        "Source distribution must contain exactly one top-level PKG-INFO",
    )
    metadata = parse_metadata(metadata_values[0], path.name)
    require(metadata["Version"] == version, "Source metadata version mismatch")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def prepare_release_evidence(
    source_root: Path,
    dist_directory: Path,
    output_directory: Path,
    tag: str,
    commit: str,
) -> dict[str, object]:
    source_root = source_root.resolve(strict=True)
    dist_directory = dist_directory.resolve(strict=True)
    output_directory = output_directory.resolve(strict=False)
    require(COMMIT_ID.fullmatch(commit) is not None, "Commit must be 40 lowercase hex")
    require(not output_directory.exists(), "Release evidence output already exists")
    require(output_directory.parent.is_dir(), "Release evidence parent must exist")
    version = validate_source_identity(source_root, tag)

    expected_names = {
        f"{ARCHIVE_NAME}-{version}-py3-none-any.whl",
        f"{ARCHIVE_NAME}-{version}.tar.gz",
    }
    artifacts = sorted(dist_directory.iterdir())
    require(
        all(path.is_file() and not path.is_symlink() for path in artifacts),
        "Distribution directory must contain only regular files",
    )
    actual_names = {path.name for path in artifacts}
    require(
        actual_names == expected_names, f"Unexpected distributions: {actual_names!r}"
    )
    wheel = next(path for path in artifacts if path.suffix == ".whl")
    sdist = next(path for path in artifacts if path.name.endswith(".tar.gz"))
    validate_wheel(wheel, version)
    validate_sdist(sdist, version)

    records = [
        {
            "file": path.name,
            "sha256": sha256(path),
            "size": path.stat().st_size,
        }
        for path in artifacts
    ]
    evidence = {
        "schemaVersion": 1,
        "project": PROJECT_NAME,
        "version": version,
        "tag": tag,
        "commit": commit,
        "artifacts": records,
    }
    output_directory.mkdir()
    evidence_path = output_directory / "release-evidence.json"
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest_records = [
        *records,
        {"file": evidence_path.name, "sha256": sha256(evidence_path)},
    ]
    manifest = "".join(
        f"{record['sha256']} *{record['file']}\n"
        for record in sorted(manifest_records, key=lambda item: str(item["file"]))
    )
    (output_directory / "SHA256SUMS.txt").write_text(manifest, encoding="utf-8")
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--dist-directory", type=Path, default=Path("dist"))
    parser.add_argument(
        "--output-directory", type=Path, default=Path("release-evidence")
    )
    arguments = parser.parse_args()
    evidence = prepare_release_evidence(
        ROOT,
        arguments.dist_directory,
        arguments.output_directory,
        arguments.tag,
        arguments.commit,
    )
    print(
        f"Release evidence passed for {evidence['project']} {evidence['version']} "
        f"at {evidence['commit']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
