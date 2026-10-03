#!/usr/bin/env python3
"""Validate release distributions and write deterministic integrity evidence."""

from __future__ import annotations

import argparse
import ast
import base64
import csv
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
import unicodedata
import zipfile
import zlib
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

from packaging.markers import Marker
from packaging.requirements import InvalidRequirement, Requirement

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
PROJECT_NAME = "bedrock-guardrail-firewall"
ARCHIVE_NAME = "bedrock_guardrail_firewall"
REPOSITORY_URL = "https://github.com/fusiontechstrategies/Bedrock-Guardrail-Firewall"
STABLE_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
COMMIT_ID = re.compile(r"^[0-9a-f]{40}$")
CHANGELOG_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
PINNED_REQUIREMENT = re.compile(
    r"([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.!+_-]*)"
)
OPTIONAL_REQUIREMENT_FILES = {
    "aws": "requirements-aws.txt",
    "presidio": "requirements-presidio.txt",
}
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


def read_release_date(source_root: Path, version: str) -> str:
    changelog = (source_root / "CHANGELOG.md").read_text(encoding="utf-8")
    matches = re.findall(
        rf"(?m)^## \[{re.escape(version)}\] - ({CHANGELOG_DATE.pattern})$",
        changelog,
    )
    require(len(matches) == 1, "Changelog release header is missing or ambiguous")
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
    read_release_date(source_root, version)
    link = re.compile(
        rf"(?m)^\[{re.escape(version)}\]: https://github\.com/"
        rf"fusiontechstrategies/Bedrock-Guardrail-Firewall/compare/.+\.\.\.v"
        rf"{re.escape(version)}$"
    )
    require(link.search(changelog) is not None, "Changelog release link is missing")
    return version


def archive_parts(name: str) -> tuple[str, ...]:
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
    stripped = name.rstrip("/")
    require(bool(stripped), "Archive contains an empty member name")
    raw_parts = tuple(stripped.split("/"))
    require(
        all(part not in {"", ".", ".."} for part in raw_parts),
        f"Archive member traverses or aliases a path: {name!r}",
    )
    for part in raw_parts:
        require(
            re.search(r"~[0-9]", part) is None,
            f"Archive member contains a Windows short-name alias: {name!r}",
        )
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


def normalize_distribution_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def canonical_optional_marker(marker: Marker | None) -> str:
    """Admit the complete reviewed conjunction, after PEP 508 parsing."""
    if marker is None:
        return ""
    rendered = str(marker)
    require(len(rendered) <= 512, "Optional marker exceeds its work budget")
    try:
        expression = ast.parse(rendered, mode="eval").body
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise ReleaseEvidenceError("Unsupported optional marker") from exc

    def terms(node):
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
            return [term for child in node.values for term in terms(child)]
        require(
            isinstance(node, ast.Compare)
            and len(node.ops) == len(node.comparators) == 1,
            "Unsupported optional marker expression",
        )
        left, right, operator = node.left, node.comparators[0], node.ops[0]
        if isinstance(left, ast.Constant) and isinstance(right, ast.Name):
            left, right = right, left
            if isinstance(operator, ast.Gt):
                operator = ast.Lt()
            elif isinstance(operator, ast.Lt):
                operator = ast.Gt()
        require(
            isinstance(left, ast.Name)
            and isinstance(right, ast.Constant)
            and isinstance(right.value, str),
            "Unsupported optional marker operands",
        )
        if left.id == "extra":
            require(
                isinstance(operator, ast.Eq)
                and right.value in OPTIONAL_REQUIREMENT_FILES,
                "Unsupported optional extra comparison",
            )
            return [("extra", "==", right.value)]
        require(
            left.id == "python_version"
            and isinstance(operator, ast.Lt)
            and right.value == "3.14",
            "Unsupported optional Python-version comparison",
        )
        return [("python_version", "<", right.value)]

    parsed = terms(expression)
    require(
        len(parsed) <= 2 and len(set(parsed)) == len(parsed),
        "Duplicate or excessive optional marker terms",
    )
    return " and ".join(
        f"{variable} {operator} {json.dumps(value)}"
        for variable, operator, value in sorted(parsed)
    )


def pinned_requirement(value: str) -> Requirement:
    require(len(value) <= 1024, "Optional requirement exceeds its work budget")
    try:
        parsed = Requirement(value)
    except (InvalidRequirement, RecursionError) as exc:
        raise ReleaseEvidenceError("Invalid PEP 508 optional requirement") from exc
    require(
        not parsed.extras
        and parsed.url is None
        and PINNED_REQUIREMENT.fullmatch(parsed.name + str(parsed.specifier))
        is not None,
        "Optional requirement is not an exact package pin",
    )
    return parsed


def parse_optional_dependencies(source_root: Path) -> list[dict[str, str]]:
    dependencies: list[dict[str, str]] = []
    normalized_names: set[str] = set()
    for group, filename in OPTIONAL_REQUIREMENT_FILES.items():
        group_count = 0
        for raw_line in (
            (source_root / filename).read_text(encoding="utf-8").splitlines()
        ):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("https://"):
                require(
                    group == "presidio" and "#sha256=" in line,
                    f"Unexpected direct requirement URL in {filename}: {line!r}",
                )
                continue
            match = PINNED_REQUIREMENT.fullmatch(line)
            require(
                match is not None,
                f"Optional requirement is not an exact package pin: {line!r}",
            )
            name, version = match.groups()
            normalized = normalize_distribution_name(name)
            require(
                normalized not in normalized_names,
                f"Duplicate optional dependency: {name}",
            )
            normalized_names.add(normalized)
            group_count += 1
            dependencies.append(
                {
                    "group": group,
                    "name": name,
                    "normalized_name": normalized,
                    "version": version,
                }
            )
        require(group_count > 0, f"No package dependencies found in {filename}")
    try:
        document = tomllib.loads((source_root / "pyproject.toml").read_text("utf-8"))
        optional = document["project"]["optional-dependencies"]
    except (ValueError, KeyError, TypeError) as exc:
        raise ReleaseEvidenceError(
            "Reviewed optional dependency metadata is invalid"
        ) from exc
    require(
        isinstance(optional, dict) and set(optional) == set(OPTIONAL_REQUIREMENT_FILES),
        "Reviewed optional dependency groups differ",
    )
    declared: dict[tuple[str, str, str], str] = {}
    for group, values in optional.items():
        require(
            isinstance(values, list) and bool(values),
            "Invalid optional dependency list",
        )
        for value in values:
            require(isinstance(value, str), "Optional dependency must be text")
            parsed = pinned_requirement(value)
            source_marker = canonical_optional_marker(parsed.marker)
            require(
                "extra" not in source_marker, "Source marker cannot select an extra"
            )
            marker = canonical_optional_marker(
                Marker(
                    (source_marker + " and " if source_marker else "")
                    + f'extra == "{group}"'
                )
            )
            key = (
                normalize_distribution_name(parsed.name),
                str(parsed.specifier)[2:],
                group,
            )
            require(key not in declared, "Duplicate reviewed optional dependency")
            declared[key] = marker
    require(
        set(declared)
        == {
            (item["normalized_name"], item["version"], item["group"])
            for item in dependencies
        },
        "Reviewed pyproject optional dependencies do not match "
        "pinned requirement files",
    )
    for item in dependencies:
        item["marker"] = declared[
            (item["normalized_name"], item["version"], item["group"])
        ]
    return sorted(dependencies, key=lambda item: item["normalized_name"])


def parse_direct_wheel_dependencies(source_root: Path) -> list[dict[str, str]]:
    dependencies: list[dict[str, str]] = []
    requirement_path = source_root / OPTIONAL_REQUIREMENT_FILES["presidio"]
    for raw_line in requirement_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line.startswith("https://"):
            continue
        url, separator, digest = line.partition("#sha256=")
        require(
            bool(separator) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
            f"Direct wheel requirement lacks an exact SHA-256 digest: {line!r}",
        )
        filename = url.rsplit("/", 1)[-1]
        require(filename.endswith(".whl"), "Direct requirement is not a wheel")
        wheel_parts = filename[:-4].split("-")
        require(
            len(wheel_parts) == 5,
            f"Direct wheel filename is not a pure Python wheel: {filename!r}",
        )
        distribution, version, python_tag, abi_tag, platform_tag = wheel_parts
        require(
            (python_tag, abi_tag, platform_tag) == ("py3", "none", "any"),
            f"Direct wheel is not platform independent: {filename!r}",
        )
        name = distribution.replace("_", "-")
        require(
            PINNED_REQUIREMENT.fullmatch(f"{name}=={version}") is not None,
            f"Direct wheel has an invalid name or version: {filename!r}",
        )
        dependencies.append(
            {
                "download_location": url,
                "group": "presidio",
                "marker": "installed only through requirements-presidio.txt",
                "name": name,
                "normalized_name": normalize_distribution_name(name),
                "sha256": digest,
                "version": version,
            }
        )
    require(
        len(dependencies) == 1,
        "requirements-presidio.txt must contain one pinned direct model wheel",
    )
    return dependencies


def parse_wheel_dependencies(document) -> list[dict[str, str]]:
    dependencies: list[dict[str, str]] = []
    normalized_names: set[str] = set()
    for raw_requirement in document.get_all("Requires-Dist") or []:
        requirement = str(raw_requirement)
        parsed = pinned_requirement(requirement)
        package, separator, marker = requirement.partition(";")
        match = PINNED_REQUIREMENT.fullmatch(package.strip())
        require(
            match is not None,
            f"Wheel dependency is not an exact package pin: {requirement!r}",
        )
        require(
            bool(separator and marker.strip()),
            "Wheel optional dependency lacks a marker",
        )
        canonical_marker = canonical_optional_marker(parsed.marker)
        groups = re.findall(r'extra == "([^"]+)"', canonical_marker)
        require(
            len(groups) == 1 and groups[0] in OPTIONAL_REQUIREMENT_FILES,
            f"Wheel dependency has an unsupported extra marker: {requirement!r}",
        )
        name, version = match.groups()
        normalized = normalize_distribution_name(name)
        require(
            normalized not in normalized_names,
            f"Duplicate wheel dependency: {name}",
        )
        normalized_names.add(normalized)
        dependencies.append(
            {
                "group": groups[0],
                "marker": canonical_marker,
                "name": name,
                "normalized_name": normalized,
                "version": version,
            }
        )
    return sorted(dependencies, key=lambda item: item["normalized_name"])


def validate_wheel(
    path: Path,
    version: str,
    expected_dependencies: list[dict[str, str]],
    source_root: Path | None = None,
    *,
    snapshot: bytes | None = None,
) -> list[dict[str, str]]:
    metadata_values: list[bytes] = []
    record_values: list[tuple[str, bytes]] = []
    required_members = {
        "bedrock_guardrail_firewall/__init__.py",
        "bedrock_guardrail_firewall/orchestrator.py",
        "bedrock_guardrail_firewall/guardrail_policy.json",
        "bedrock_guardrail_firewall/guardrail_policy_profiles.json",
        "bedrock_guardrail_firewall/py.typed",
    }
    with zipfile.ZipFile(
        io.BytesIO(snapshot) if snapshot is not None else path
    ) as archive:
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
            if source_root is not None:
                if name in required_members:
                    require(
                        value == (source_root / name.split("/", 1)[1]).read_bytes(),
                        f"Wheel source differs from reviewed source: {name!r}",
                    )
                else:
                    metadata_prefix = f"{ARCHIVE_NAME}-{version}.dist-info/"
                    allowed_metadata = {
                        "METADATA",
                        "WHEEL",
                        "RECORD",
                        "entry_points.txt",
                        "top_level.txt",
                        "licenses/LICENSE",
                        "licenses/NOTICE",
                    }
                    require(
                        name.startswith(metadata_prefix)
                        and name[len(metadata_prefix) :] in allowed_metadata,
                        f"Wheel contains an unreviewed member: {name!r}",
                    )
                    if name.endswith("/entry_points.txt"):
                        require(
                            value.decode("utf-8").strip()
                            == "[console_scripts]\nbedrock-guardrail-firewall = "
                            "bedrock_guardrail_firewall.orchestrator:main",
                            "Wheel contains unexpected installation entry points",
                        )
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
    dependencies = parse_wheel_dependencies(metadata)
    expected_identity = {
        (item["normalized_name"], item["version"], item["group"], item["marker"])
        for item in expected_dependencies
    }
    actual_identity = {
        (item["normalized_name"], item["version"], item["group"], item["marker"])
        for item in dependencies
    }
    require(
        actual_identity == expected_identity,
        "Wheel optional dependencies do not match the pinned requirement files",
    )

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
    return dependencies


def reviewed_sdist_sources(source_root: Path) -> dict[str, bytes]:
    """Interpret only static inclusion rules; never import or run build hooks."""
    paths = {"__init__.py", "orchestrator.py", "pyproject.toml", "MANIFEST.in"}
    manifest = source_root / "MANIFEST.in"
    require(
        manifest.is_file() and not manifest.is_symlink(),
        "Reviewed MANIFEST.in is missing",
    )
    for line in manifest.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if not parts or parts[0].startswith("#"):
            continue
        if parts[0] == "include" and len(parts) >= 2:
            for pattern in parts[1:]:
                require(
                    "/" not in pattern and "\\" not in pattern,
                    "Unsupported manifest pattern",
                )
                paths.update(
                    path.name for path in source_root.glob(pattern) if path.is_file()
                )
        elif parts[0] == "recursive-include" and len(parts) >= 3:
            directory = parts[1]
            require(
                not (source_root / directory).is_symlink(),
                "Reviewed source directory is linked",
            )
            require(
                directory in {"docs", "examples", "scripts", "tests"},
                "Unsupported manifest directory",
            )
            for pattern in parts[2:]:
                require(
                    "/" not in pattern and "\\" not in pattern,
                    "Unsupported manifest pattern",
                )
                paths.update(
                    path.relative_to(source_root).as_posix()
                    for path in (source_root / directory).rglob(pattern)
                    if path.is_file()
                )
        else:
            raise ReleaseEvidenceError("Unsupported source manifest directive")
    values = {}
    for name in sorted(paths):
        validate_public_member(name)
        path = source_root / name
        require(
            path.is_file()
            and all(not item.is_symlink() for item in (path, *path.parents)),
            f"Reviewed source is missing or linked: {name!r}",
        )
        values[name] = path.read_bytes()
    return values


def generated_sdist_members(
    source_root: Path, sources: dict[str, bytes]
) -> dict[str, bytes]:
    """Construct the pinned backend's static metadata without invoking it."""
    project = tomllib.loads(sources["pyproject.toml"].decode("utf-8"))["project"]
    require(not project.get("dynamic"), "Dynamic project metadata is not approved")
    require(project.get("name") == PROJECT_NAME, "Unexpected source project name")
    fields = [
        ("Metadata-Version", "2.4"),
        ("Name", project["name"]),
        ("Version", project["version"]),
    ]
    if project.get("description"):
        fields.append(("Summary", project["description"]))
    authors = project.get("authors", [])
    require(
        all(set(item) <= {"name"} for item in authors), "Unsupported author metadata"
    )
    if authors:
        fields.append(("Author", ", ".join(item["name"] for item in authors)))
    require(project.get("license") == "Apache-2.0", "Unsupported source license")
    fields.append(("License-Expression", project["license"]))
    fields += [
        ("Project-URL", f"{name}, {value}")
        for name, value in project.get("urls", {}).items()
    ]
    if project.get("keywords"):
        fields.append(("Keywords", ",".join(project["keywords"])))
    fields += [("Classifier", value) for value in project.get("classifiers", [])]
    fields += [
        ("Requires-Python", project["requires-python"]),
        ("Description-Content-Type", "text/markdown"),
    ]
    license_files = project.get("license-files", [])
    fields += [("License-File", value) for value in license_files]
    optional = project.get("optional-dependencies", {})
    requirements = []
    for group, items in optional.items():
        fields.append(("Provides-Extra", group))
        markers = {}
        for raw in items:
            req = Requirement(raw)
            marker = str(req.marker) if req.marker else ""
            req.marker = None
            rendered = str(req)
            fields.append(
                (
                    "Requires-Dist",
                    rendered
                    + "; "
                    + (marker + " and " if marker else "")
                    + f'extra == "{group}"',
                )
            )
            markers.setdefault(marker, []).append(rendered)
        requirements.append("\n[" + group + "]\n")
        requirements.extend(item + "\n" for item in markers.pop("", []))
        for marker, items in sorted(markers.items()):
            requirements.append("\n[" + group + ":" + marker + "]\n")
            requirements.extend(item + "\n" for item in items)
    if license_files:
        fields.append(("Dynamic", "license-file"))
    require(project.get("readme") == "README.md", "Unsupported source README")
    require(
        all(
            isinstance(value, str) and "\n" not in value and "\r" not in value
            for _, value in fields
        ),
        "Invalid generated metadata field",
    )
    readme = sources["README.md"].decode("utf-8").replace("\r\n", "\n")
    metadata = (
        "".join(f"{key}: {value}\n" for key, value in fields) + "\n" + readme
    ).encode("utf-8")
    egg = ARCHIVE_NAME + ".egg-info/"
    generated = {
        "PKG-INFO": metadata,
        egg + "PKG-INFO": metadata,
        egg + "dependency_links.txt": b"\n",
        egg + "entry_points.txt": (
            b"[console_scripts]\nbedrock-guardrail-firewall = "
            b"bedrock_guardrail_firewall.orchestrator:main\n"
        ),
        egg + "top_level.txt": (ARCHIVE_NAME + "\n").encode(),
        "setup.cfg": b"[egg_info]\ntag_build = \ntag_date = 0\n\n",
    }
    require(
        project.get("scripts")
        == {
            "bedrock-guardrail-firewall": "bedrock_guardrail_firewall.orchestrator:main"
        },
        "Unsupported source entry points",
    )
    if optional:
        generated[egg + "requires.txt"] = "".join(requirements).encode()
    package_files = (
        "__init__.py",
        "orchestrator.py",
        "guardrail_policy.json",
        "guardrail_policy_profiles.json",
        "py.typed",
    )
    source_list = (
        set(sources)
        | {"./" + name for name in package_files}
        | {name for name in generated if name.startswith(egg)}
        | {egg + "SOURCES.txt"}
    )
    # setuptools FileList sorts by directory, then basename, preserving ./ aliases
    # in metadata only. Archive paths themselves must remain canonical.
    generated[egg + "SOURCES.txt"] = (
        "\n".join(
            sorted(
                source_list,
                key=lambda name: (name.rpartition("/")[0], name.rpartition("/")[2]),
            )
        )
    ).encode()
    return generated


MAX_RELEASE_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_RELEASE_TAR_BYTES = 128 * 1024 * 1024


def artifact_snapshot(path: Path) -> bytes:
    """Bind validation, digest and size to bounded bytes from one descriptor."""
    if os.name == "nt":
        import ctypes
        import ctypes.wintypes as wintypes
        import msvcrt

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.CreateFileW(str(path), 0x80000000, 3, None, 3, 0x00200000, None)
        require(handle != wintypes.HANDLE(-1).value, "Unable to open distribution")
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            handle = None
        finally:
            if handle is not None:
                kernel.CloseHandle(handle)
    else:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and not (
                getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            ),
            "Distribution must be a single unlinked regular file",
        )
        require(
            info.st_size <= MAX_RELEASE_ARTIFACT_BYTES,
            "Distribution exceeds byte budget",
        )
        value = stream.read(MAX_RELEASE_ARTIFACT_BYTES + 1)
        require(
            len(value) <= MAX_RELEASE_ARTIFACT_BYTES, "Distribution exceeds byte budget"
        )
        return value


def checked_tar_container(path: Path, compressed: bytes) -> bytes:
    require(
        compressed[:3] == b"\x1f\x8b\x08" and len(compressed) >= 18,
        "Source distribution must be one gzip stream",
    )
    flags = compressed[3]
    require(flags in {0, 8}, "Unapproved gzip extra, comment or flags")
    if flags == 8:
        end = compressed.find(b"\0", 10, 1035)
        require(
            end >= 10 and compressed[10:end] == path.name[:-3].encode(),
            "Unapproved gzip filename",
        )
    try:
        decoder = zlib.decompressobj(31)
        raw = decoder.decompress(compressed, MAX_RELEASE_TAR_BYTES + 1)
    except zlib.error as exc:
        raise ReleaseEvidenceError("Invalid source gzip stream") from exc
    require(
        len(raw) <= MAX_RELEASE_TAR_BYTES
        and decoder.eof
        and not decoder.unused_data
        and not decoder.unconsumed_tail,
        "Source gzip has trailing data or exceeds budget",
    )
    offset = 0
    while offset + 512 <= len(raw):
        block = raw[offset : offset + 512]
        if block == b"\0" * 512:
            require(
                len(raw) - offset >= 1024
                and len(raw) % 512 == 0
                and not any(raw[offset:]),
                "Source tar has trailing data or incomplete end markers",
            )
            return raw
        try:
            member = tarfile.TarInfo.frombuf(block, "utf-8", "strict")
        except (tarfile.HeaderError, UnicodeError) as exc:
            raise ReleaseEvidenceError("Invalid source tar header") from exc
        require(
            0 <= member.size <= MAX_RELEASE_TAR_BYTES, "Source tar size exceeds budget"
        )
        payload_end = offset + 512 + member.size
        next_offset = offset + 512 + ((member.size + 511) // 512) * 512
        require(next_offset <= len(raw), "Truncated source tar member")
        require(
            not any(raw[payload_end:next_offset]), "Noncanonical tar member padding"
        )
        require(
            (member.isfile() or member.isdir())
            and member.uid == member.gid == member.mtime == 0
            and member.uname == member.gname == member.linkname == ""
            and member.devmajor == member.devminor == 0
            and not any(block[500:]),
            "Unapproved source tar type, ownership or timestamp metadata",
        )
        offset = next_offset
    raise ReleaseEvidenceError("Source tar is missing complete end markers")


def validate_sdist(
    path: Path,
    version: str,
    source_root: Path | None = None,
    *,
    snapshot: bytes | None = None,
) -> None:
    expected_root = f"{ARCHIVE_NAME}-{version}"
    expected = None
    generated = {}
    if source_root is not None:
        expected = reviewed_sdist_sources(source_root)
        generated = generated_sdist_members(source_root, expected)
        expected = {**expected, **generated}
    metadata_values = []
    names = set()
    files = set()
    allowed_directories = {expected_root}
    if expected is not None:
        for name in expected:
            allowed_directories.update(
                expected_root + "/" + parent.as_posix()
                for parent in PurePosixPath(name).parents
                if parent.as_posix() != "."
            )
    compressed = artifact_snapshot(path) if snapshot is None else snapshot
    raw = checked_tar_container(path, compressed)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        require(not archive.pax_headers, "Global PAX metadata is not approved")
        portable_names = set()
        for member in archive:
            require(not member.pax_headers, "Unapproved member PAX metadata")
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
                parts[0] == expected_root, "Source distribution has an unexpected root"
            )
            require(
                member.isfile() or member.isdir(),
                "Source distribution contains a link or device",
            )
            if member.isdir():
                require(
                    expected is None or name in allowed_directories,
                    "Source distribution contains an unreviewed directory",
                )
                require(
                    member.mode == 0o755 and member.size == 0,
                    "Source distribution has unsafe directory metadata",
                )
                continue
            relative = "/".join(parts[1:])
            files.add(relative)
            if expected is not None:
                require(
                    relative in expected,
                    f"Non-canonical or unreviewed source member: {relative!r}",
                )
                allowed_modes = {0o644}
                if (
                    relative not in generated
                    and (source_root / relative).stat().st_mode & 0o111
                ):
                    allowed_modes.add(0o755)
                require(
                    member.mode in allowed_modes,
                    "Source distribution has unsafe file mode",
                )
                # Platform newline translation is an explicit generated-metadata
                # exception only. Every source-controlled byte remains exact.
                approved = expected[relative]
                alternatives = (
                    {approved}
                    if relative not in generated
                    else {
                        approved,
                        approved.replace(b"\n", b"\r\n"),
                        approved.replace(b"\n", b"\r\r\n"),
                    }
                )
                require(
                    member.size in {len(item) for item in alternatives},
                    f"Source distribution differs from reviewed source: {relative!r}",
                )
            handle = archive.extractfile(member)
            require(handle is not None, "Unable to read source member")
            value = handle.read(member.size + 1)
            require(len(value) == member.size, "Source member is truncated")
            if expected is not None:
                require(
                    value in alternatives,
                    f"Source distribution differs from reviewed source: {relative!r}",
                )
            if relative == "PKG-INFO":
                metadata_values.append(value)
    require(
        len(metadata_values) == 1,
        "Source distribution must contain exactly one top-level PKG-INFO",
    )
    if expected is not None:
        require(
            files == set(expected),
            "Source distribution is missing reviewed source or metadata",
        )
    metadata = parse_metadata(metadata_values[0], path.name)
    require(metadata["Version"] == version, "Source metadata version mismatch")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def dependency_spdx_id(index: int, normalized_name: str) -> str:
    safe_name = re.sub(r"[^A-Za-z0-9.-]", "-", normalized_name)
    return f"SPDXRef-Dependency-{index:03d}-{safe_name}"


def build_spdx(
    version: str,
    release_date: str,
    wheel_digest: str,
    dependencies: list[dict[str, str]],
) -> bytes:
    root_id = "SPDXRef-Package"
    packages: list[dict[str, object]] = [
        {
            "SPDXID": root_id,
            "checksums": [{"algorithm": "SHA256", "checksumValue": wheel_digest}],
            "copyrightText": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceLocator": (f"pkg:pypi/{PROJECT_NAME}@{version}"),
                    "referenceType": "purl",
                }
            ],
            "filesAnalyzed": False,
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0",
            "name": PROJECT_NAME,
            "supplier": "Organization: Fusion Technology Strategies",
            "versionInfo": version,
        }
    ]
    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_id,
        }
    ]
    for index, dependency in enumerate(dependencies, start=1):
        package_id = dependency_spdx_id(index, dependency["normalized_name"])
        package: dict[str, object] = {
            "SPDXID": package_id,
            "copyrightText": "NOASSERTION",
            "downloadLocation": dependency.get("download_location", "NOASSERTION"),
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "name": dependency["name"],
            "supplier": "NOASSERTION",
            "versionInfo": dependency["version"],
        }
        if "download_location" in dependency:
            package["checksums"] = [
                {"algorithm": "SHA256", "checksumValue": dependency["sha256"]}
            ]
        else:
            package["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceLocator": (
                        f"pkg:pypi/{dependency['normalized_name']}@"
                        f"{dependency['version']}"
                    ),
                    "referenceType": "purl",
                }
            ]
        packages.append(package)
        relationships.append(
            {
                "comment": (
                    f"Optional dependency group {dependency['group']!r}; "
                    f"wheel marker: {dependency['marker']}"
                ),
                "spdxElementId": package_id,
                "relationshipType": "OPTIONAL_DEPENDENCY_OF",
                "relatedSpdxElement": root_id,
            }
        )
    document = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": f"{release_date}T00:00:00Z",
            "creators": [
                "Organization: Fusion Technology Strategies",
                "Tool: scripts/prepare_release_evidence.py",
            ],
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": (
            f"{REPOSITORY_URL}/releases/tag/v{version}#spdx-{wheel_digest}"
        ),
        "name": f"{PROJECT_NAME}-{version}",
        "packages": packages,
        "relationships": relationships,
        "spdxVersion": "SPDX-2.3",
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


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
    release_date = read_release_date(source_root, version)
    expected_dependencies = parse_optional_dependencies(source_root)
    direct_wheel_dependencies = parse_direct_wheel_dependencies(source_root)

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
    snapshots = {path.name: artifact_snapshot(path) for path in artifacts}
    dependencies = [
        *validate_wheel(
            wheel,
            version,
            expected_dependencies,
            source_root,
            snapshot=snapshots[wheel.name],
        ),
        *direct_wheel_dependencies,
    ]
    validate_sdist(sdist, version, source_root, snapshot=snapshots[sdist.name])
    require(
        all(artifact_snapshot(path) == snapshots[path.name] for path in artifacts),
        "Distribution changed after validation",
    )

    records = [
        {
            "file": path.name,
            "sha256": hashlib.sha256(snapshots[path.name]).hexdigest(),
            "size": len(snapshots[path.name]),
        }
        for path in artifacts
    ]
    output_directory.mkdir()
    sbom_path = output_directory / f"{PROJECT_NAME}-{version}.spdx.json"
    sbom_path.write_bytes(
        build_spdx(
            version,
            release_date,
            hashlib.sha256(snapshots[wheel.name]).hexdigest(),
            dependencies,
        )
    )
    sbom_record = {
        "file": sbom_path.name,
        "sha256": sha256(sbom_path),
        "size": sbom_path.stat().st_size,
    }
    evidence = {
        "schemaVersion": 1,
        "project": PROJECT_NAME,
        "version": version,
        "tag": tag,
        "commit": commit,
        "artifacts": records,
        "sbom": sbom_record,
    }
    evidence_path = output_directory / "release-evidence.json"
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest_records = [
        *records,
        sbom_record,
        {"file": evidence_path.name, "sha256": sha256(evidence_path)},
    ]
    manifest = "".join(
        f"{record['sha256']} *{record['file']}\n"
        for record in sorted(manifest_records, key=lambda item: str(item["file"]))
    )
    (output_directory / "SHA256SUMS.txt").write_text(manifest, encoding="utf-8")
    require(
        all(artifact_snapshot(path) == snapshots[path.name] for path in artifacts),
        "Distribution changed during evidence generation",
    )
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-directory", type=Path, default=ROOT)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--dist-directory", type=Path, default=Path("dist"))
    parser.add_argument(
        "--output-directory", type=Path, default=Path("release-evidence")
    )
    arguments = parser.parse_args()
    evidence = prepare_release_evidence(
        arguments.source_directory,
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
