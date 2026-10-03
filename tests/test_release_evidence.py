import base64
import csv
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts import prepare_release_evidence as release

VERSION = "4.1.1"
TAG = f"v{VERSION}"
COMMIT = "a" * 40
METADATA = (
    f"""Metadata-Version: 2.4
Name: bedrock-guardrail-firewall
Version: {VERSION}
License-Expression: Apache-2.0
Requires-Python: >=3.10
Description-Content-Type: text/markdown
Provides-Extra: aws
Requires-Dist: boto3==1.43.82; extra == "aws"
Requires-Dist: botocore==1.43.82; extra == "aws"
Provides-Extra: presidio
"""
    'Requires-Dist: presidio-analyzer==2.2.364; python_version < "3.14" '
    'and extra == "presidio"\n'
    'Requires-Dist: spacy==3.8.16; python_version < "3.14" '
    'and extra == "presidio"\n\n'
    "Synthetic package description.\n"
).encode()


def canonical_wheel_info(name: str) -> zipfile.ZipInfo:
    """Independent fixture for the observed pinned backend's Unix convention."""
    member = zipfile.ZipInfo(name)
    member.create_system = 3
    member.external_attr = (0o100664 if name.endswith("/RECORD") else 0o100644) << 16
    return member


class ReleaseEvidenceTests(unittest.TestCase):
    def test_wheel_rejects_unreviewed_installation_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_source(root)
            self.make_distributions(root / "dist")
            wheel = next((root / "dist").glob("*.whl"))
            with zipfile.ZipFile(wheel, "a") as archive:
                archive.writestr(
                    canonical_wheel_info("injected.pth"), "import injected"
                )
            with self.assertRaisesRegex(
                release.ReleaseEvidenceError, "unreviewed member"
            ):
                release.validate_wheel(
                    wheel, VERSION, release.parse_optional_dependencies(root), root
                )

    def test_self_consistent_wheel_cannot_substitute_reviewed_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_source(root)
            self.make_distributions(root / "dist")
            (root / "orchestrator.py").write_text("replacement source")
            wheel = next((root / "dist").glob("*.whl"))
            with self.assertRaisesRegex(
                release.ReleaseEvidenceError, "differs from reviewed source"
            ):
                release.validate_wheel(
                    wheel, VERSION, release.parse_optional_dependencies(root), root
                )

    def test_sdist_rejects_windows_active_case_aliases(self):
        for alias in ("Setup.py", "setup.PY", "inject.PTH", "PyProject.toml"):
            with self.subTest(alias=alias), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.make_source(root)
                self.make_distributions(root / "dist")
                sdist = next((root / "dist").glob("*.tar.gz"))
                with tarfile.open(sdist, "r:gz") as archive:
                    entries = [
                        (
                            member,
                            archive.extractfile(member).read()
                            if member.isfile()
                            else b"",
                        )
                        for member in archive.getmembers()
                    ]
                with tarfile.open(sdist, "w:gz") as archive:
                    for member, data in entries:
                        archive.addfile(
                            member, io.BytesIO(data) if member.isfile() else None
                        )
                    data = b"raise RuntimeError('unreviewed')"
                    member = tarfile.TarInfo(
                        f"bedrock_guardrail_firewall-{VERSION}/{alias}"
                    )
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
                with self.assertRaisesRegex(
                    release.ReleaseEvidenceError, "Non-canonical|non-portable duplicate"
                ):
                    release.validate_sdist(sdist, VERSION, root)

    def test_archive_rejects_ntfs_streams_in_any_component(self):
        from scripts import normalize_sdist as normalizer

        for alias in (
            "package/setup.py::$DATA",
            "package/nested:stream/file.py",
            "package/normal.py:payload",
        ):
            with self.subTest(alias=alias):
                with self.assertRaises(release.ReleaseEvidenceError):
                    release.archive_parts(alias)
                with self.assertRaises(normalizer.SdistNormalizationError):
                    normalizer.validate_member_name(alias)

    def make_source(self, root: Path) -> None:
        (root / "scripts").mkdir()
        (root / "pyproject.toml").write_text(
            '[build-system]\nrequires = ["setuptools==84.0.0", "wheel==0.48.0"]\n'
            'build-backend = "setuptools.build_meta"\n'
            f'[project]\nname = "bedrock-guardrail-firewall"\nversion = "{VERSION}"\n'
            'readme = "README.md"\nlicense = "Apache-2.0"\nlicense-files = []\n'
            'requires-python = ">=3.10"\n'
            "[project.scripts]\n"
            "bedrock-guardrail-firewall = "
            '"bedrock_guardrail_firewall.orchestrator:main"\n'
            "[project.optional-dependencies]\n"
            'aws = ["boto3==1.43.82", "botocore==1.43.82"]\n'
            "presidio = [\"presidio-analyzer==2.2.364; python_version < '3.14'\", "
            "\"spacy==3.8.16; python_version < '3.14'\"]\n",
            encoding="utf-8",
        )
        (root / "orchestrator.py").write_text(
            f'__version__ = "{VERSION}"\n', encoding="utf-8"
        )
        for name in (
            "__init__.py",
            "guardrail_policy.json",
            "guardrail_policy_profiles.json",
            "py.typed",
        ):
            (root / name).write_bytes(b"synthetic")
        (root / "scripts" / "validate_installed_package.py").write_text(
            f'EXPECTED_VERSION = "{VERSION}"\n', encoding="utf-8"
        )
        (root / "CHANGELOG.md").write_text(
            f"## [{VERSION}] - 2026-08-27\n\n"
            f"[{VERSION}]: https://github.com/fusiontechstrategies/"
            f"Bedrock-Guardrail-Firewall/compare/v4.0.0...v{VERSION}\n",
            encoding="utf-8",
        )
        (root / "requirements-aws.txt").write_text(
            "boto3==1.43.82\nbotocore==1.43.82\n", encoding="utf-8"
        )
        (root / "requirements-presidio.txt").write_text(
            "presidio-analyzer==2.2.364\nspacy==3.8.16\n"
            "https://example.invalid/"
            "en_core_web_sm-3.8.0-py3-none-any.whl#sha256=" + "a" * 64 + "\n",
            encoding="utf-8",
        )

        (root / "MANIFEST.in").write_text(
            "include README.md CHANGELOG.md guardrail_policy.json "
            "guardrail_policy_profiles.json py.typed requirements*.txt\n"
            "recursive-include scripts *.py\n"
        )
        (root / "README.md").write_bytes(b"Synthetic package description.\n")

    def make_distributions(self, dist: Path) -> None:
        dist.mkdir()
        wheel = dist / f"bedrock_guardrail_firewall-{VERSION}-py3-none-any.whl"
        dist_info = f"bedrock_guardrail_firewall-{VERSION}.dist-info"
        wheel_files = {
            f"bedrock_guardrail_firewall/{name}": (dist.parent / name).read_bytes()
            for name in (
                "__init__.py",
                "orchestrator.py",
                "guardrail_policy.json",
                "guardrail_policy_profiles.json",
                "py.typed",
            )
        }
        wheel_files[f"{dist_info}/METADATA"] = METADATA
        wheel_files[f"{dist_info}/WHEEL"] = (
            b"Wheel-Version: 1.0\nGenerator: setuptools (84.0.0)\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n\n"
        )
        wheel_files[f"{dist_info}/top_level.txt"] = b"bedrock_guardrail_firewall\n"
        wheel_files[f"{dist_info}/entry_points.txt"] = (
            b"[console_scripts]\nbedrock-guardrail-firewall = "
            b"bedrock_guardrail_firewall.orchestrator:main\n"
        )
        record_name = f"{dist_info}/RECORD"
        record_output = io.StringIO(newline="")
        writer = csv.writer(record_output, lineterminator="\n")
        for name, value in sorted(wheel_files.items()):
            digest = base64.urlsafe_b64encode(hashlib.sha256(value).digest())
            writer.writerow(
                [name, "sha256=" + digest.rstrip(b"=").decode(), str(len(value))]
            )
        writer.writerow([record_name, "", ""])
        wheel_files[record_name] = record_output.getvalue().encode()
        with zipfile.ZipFile(wheel, mode="w") as archive:
            for name, value in wheel_files.items():
                archive.writestr(canonical_wheel_info(name), value)

        sdist = dist / f"bedrock_guardrail_firewall-{VERSION}.tar.gz"
        with tarfile.open(sdist, mode="w:gz") as archive:
            root = f"bedrock_guardrail_firewall-{VERSION}"
            sources = release.reviewed_sdist_sources(dist.parent)
            expected = {
                **sources,
                **release.generated_sdist_members(dist.parent, sources),
            }
            for name, value in expected.items():
                member = tarfile.TarInfo(f"{root}/{name}")
                member.size = len(value)
                archive.addfile(member, io.BytesIO(value))
        from scripts.normalize_sdist import normalize_sdist

        normalize_sdist(sdist, 0)

    def test_valid_artifacts_create_covered_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_source(root)
            dist = root / "dist"
            self.make_distributions(dist)
            output = root / "evidence"
            document = release.prepare_release_evidence(root, dist, output, TAG, COMMIT)
            self.assertEqual(document["version"], VERSION)
            self.assertEqual(document["commit"], COMMIT)
            saved = json.loads(
                (output / "release-evidence.json").read_text(encoding="utf-8")
            )
            self.assertEqual(saved, document)
            sbom_path = output / f"bedrock-guardrail-firewall-{VERSION}.spdx.json"
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            self.assertEqual(sbom["spdxVersion"], "SPDX-2.3")
            self.assertEqual(sbom["dataLicense"], "CC0-1.0")
            self.assertEqual(len(sbom["packages"]), 6)
            dependency_relationships = [
                item
                for item in sbom["relationships"]
                if item["relationshipType"] == "OPTIONAL_DEPENDENCY_OF"
            ]
            self.assertEqual(len(dependency_relationships), 5)
            self.assertEqual(
                {item["name"] for item in sbom["packages"][1:]},
                {
                    "boto3",
                    "botocore",
                    "en-core-web-sm",
                    "presidio-analyzer",
                    "spacy",
                },
            )
            model = next(
                item for item in sbom["packages"] if item["name"] == "en-core-web-sm"
            )
            self.assertEqual(
                model["downloadLocation"],
                "https://example.invalid/en_core_web_sm-3.8.0-py3-none-any.whl",
            )
            self.assertEqual(
                model["checksums"],
                [{"algorithm": "SHA256", "checksumValue": "a" * 64}],
            )
            self.assertEqual(document["sbom"]["file"], sbom_path.name)
            manifest = (output / "SHA256SUMS.txt").read_text(encoding="utf-8")
            self.assertEqual(len(manifest.splitlines()), 4)
            self.assertIn("*release-evidence.json", manifest)
            self.assertIn(f"*{sbom_path.name}", manifest)

    def test_optional_requirements_must_be_exact_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_source(root)
            (root / "requirements-aws.txt").write_text(
                "boto3>=1.43.82\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                release.ReleaseEvidenceError, "not an exact package pin"
            ):
                release.parse_optional_dependencies(root)

    def test_direct_model_wheel_requires_sha256(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_source(root)
            (root / "requirements-presidio.txt").write_text(
                "presidio-analyzer==2.2.364\nspacy==3.8.16\n"
                "https://example.invalid/"
                "en_core_web_sm-3.8.0-py3-none-any.whl\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                release.ReleaseEvidenceError, "Unexpected direct requirement URL"
            ):
                release.parse_optional_dependencies(root)

    def test_direct_model_wheel_must_be_platform_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_source(root)
            (root / "requirements-presidio.txt").write_text(
                "presidio-analyzer==2.2.364\nspacy==3.8.16\n"
                "https://example.invalid/"
                "en_core_web_sm-3.8.0-cp312-cp312-win_amd64.whl#sha256="
                + "a" * 64
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                release.ReleaseEvidenceError, "not platform independent"
            ):
                release.parse_direct_wheel_dependencies(root)

    def test_wheel_dependencies_must_match_requirement_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_source(root)
            (root / "requirements-aws.txt").write_text(
                "boto3==1.43.81\nbotocore==1.43.82\n", encoding="utf-8"
            )
            dist = root / "dist"
            self.make_distributions(dist)
            with self.assertRaisesRegex(release.ReleaseEvidenceError, "do not match"):
                release.prepare_release_evidence(
                    root, dist, root / "evidence", TAG, COMMIT
                )

    def test_release_tag_must_match_stable_source_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_source(root)
            with self.assertRaisesRegex(release.ReleaseEvidenceError, "does not match"):
                release.validate_source_identity(root, "v4.1.2")

    def test_archive_path_traversal_is_rejected(self):
        with self.assertRaisesRegex(release.ReleaseEvidenceError, "traverses"):
            release.archive_parts("../private.txt")

    def test_archive_windows_device_name_is_rejected(self):
        with self.assertRaisesRegex(release.ReleaseEvidenceError, "reserved Windows"):
            release.archive_parts("package-1.0/CON.txt")

    def test_existing_evidence_directory_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_source(root)
            dist = root / "dist"
            self.make_distributions(dist)
            output = root / "evidence"
            output.mkdir()
            with self.assertRaisesRegex(release.ReleaseEvidenceError, "already exists"):
                release.prepare_release_evidence(root, dist, output, TAG, COMMIT)

    def test_distribution_directory_rejects_subdirectories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_source(root)
            dist = root / "dist"
            self.make_distributions(dist)
            (dist / "unexpected").mkdir()
            with self.assertRaisesRegex(release.ReleaseEvidenceError, "regular files"):
                release.prepare_release_evidence(
                    root, dist, root / "evidence", TAG, COMMIT
                )


if __name__ == "__main__":
    unittest.main()
