from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import io
import os
import struct
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import orchestrator as app
from scripts import normalize_sdist as normalizer
from scripts import prepare_release_evidence as release
from scripts import verify_release_handoff as handoff
from tests.test_final_read_boundaries import remove_link, replace_directory_with_link
from tests.test_orchestrator import TEST_KEY, base_config
from tests import test_release_evidence as release_fixtures

COMMIT, TAG, VERSION = (
    release_fixtures.COMMIT,
    release_fixtures.TAG,
    release_fixtures.VERSION,
)


def rewrite_wheel(path, changes):
    with zipfile.ZipFile(path) as archive:
        values = {name: archive.read(name) for name in archive.namelist()}
    values.update(changes)
    record = next(name for name in values if name.endswith("/RECORD"))
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    for name, value in sorted(values.items()):
        if name != record:
            digest = (
                base64.urlsafe_b64encode(hashlib.sha256(value).digest())
                .rstrip(b"=")
                .decode()
            )
            writer.writerow([name, "sha256=" + digest, len(value)])
    writer.writerow([record, "", ""])
    values[record] = stream.getvalue().encode()
    with zipfile.ZipFile(path, "w") as archive:
        for name, value in values.items():
            archive.writestr(release_fixtures.canonical_wheel_info(name), value)


class DataStartupBoundaryTests(unittest.TestCase):
    def test_startup_leaf_swap_after_parent_pin_never_writes_target(self):
        for injected in (True, False):
            with (
                self.subTest(injected=injected),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory).resolve()
                requested, target = root / "requested", root / "target"
                requested.mkdir(mode=0o700)
                target.mkdir(mode=0o700)
                opener = app._open_private_key
                redirected = False

                def race(
                    name,
                    *args,
                    opener=opener,
                    requested=requested,
                    target=target,
                    **kwargs,
                ):
                    nonlocal redirected
                    if (
                        Path(name) == requested
                        and kwargs.get("parent_fd") is not None
                        and not redirected
                    ):
                        replace_directory_with_link(requested, target)
                        redirected = True
                    return opener(name, *args, **kwargs)

                try:
                    with (
                        patch.object(app, "_open_private_key", side_effect=race),
                        self.assertRaises(
                            (app.ConfigurationError, app.StorageError, OSError)
                        ),
                    ):
                        app.BedrockGuardrailSystem(
                            base_config(requested),
                            privacy_key=TEST_KEY if injected else None,
                        )
                    self.assertTrue(redirected)
                    self.assertEqual(list(target.iterdir()), [])
                finally:
                    if redirected:
                        remove_link(requested)

    def test_public_configuration_never_adopts_redirected_canonical_namespace(self):
        for injected in (True, False):
            with (
                self.subTest(injected=injected),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory).resolve()
                requested, target = root / "requested", root / "target"
                requested.mkdir(mode=0o700)
                target.mkdir(mode=0o700)
                redirected = False
                original = app._reject_path_links

                def race(path, original=original, requested=requested, target=target):
                    nonlocal redirected
                    original(path)
                    if Path(path) == requested and not redirected:
                        replace_directory_with_link(requested, target)
                        redirected = True

                try:
                    with (
                        patch.object(app, "_reject_path_links", side_effect=race),
                        patch.dict(
                            os.environ,
                            {
                                "GUARDRAIL_AWS_MODE": "disabled",
                                "GUARDRAIL_PRESIDIO_MODE": "disabled",
                            },
                            clear=True,
                        ),
                    ):
                        config = app.RuntimeConfig.from_env(data_dir=str(requested))
                    self.assertTrue(redirected)
                    self.assertEqual(config.data_dir, requested)
                    with self.assertRaises(
                        (app.ConfigurationError, app.StorageError, OSError)
                    ):
                        app.BedrockGuardrailSystem(
                            config, privacy_key=TEST_KEY if injected else None
                        )
                    self.assertEqual(list(target.iterdir()), [])
                finally:
                    if redirected:
                        remove_link(requested)

    def test_startup_pins_before_key_and_stores_and_refuses_missing_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "new-data"
            calls = []
            opener = app._open_private_key

            def opened(name, *args, **kwargs):
                if Path(name).name == "privacy.key":
                    self.assertIsNotNone(kwargs.get("parent_fd"))
                    self.assertTrue(path.is_dir())
                    calls.append(Path(name))
                return opener(name, *args, **kwargs)

            with patch.object(app, "_open_private_key", side_effect=opened):
                system = app.BedrockGuardrailSystem(base_config(path))
            self.assertTrue(calls)
            self.assertEqual(system.config.data_dir, path)
            self.assertEqual(system.behavior.path.parent, path)
            self.assertEqual(system.audit.audit_dir.parent, path)
            self.assertEqual(system.reviews.local_dir.parent, path)
            self.assertEqual(system.incidents.local_dir.parent, path)
            with self.assertRaises((app.ConfigurationError, app.StorageError, OSError)):
                app.BedrockGuardrailSystem(
                    base_config(root / "missing" / "data"), privacy_key=TEST_KEY
                )
            self.assertFalse((root / "missing").exists())

    @unittest.skipIf(os.name == "nt", "POSIX owner/mode control")
    def test_writable_namespace_refused_even_with_injected_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            root.chmod(0o777)
            try:
                with self.assertRaises(app.StorageError):
                    app.BedrockGuardrailSystem(
                        base_config(root / "data"), privacy_key=TEST_KEY
                    )
                self.assertFalse((root / "data").exists())
            finally:
                root.chmod(0o700)


class ArchiveBudgetTests(unittest.TestCase):
    def make_tar(self, path, values, pax=False):
        with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            for index, value in enumerate(values):
                member = tarfile.TarInfo(f"package/file{index}.txt")
                member.size = len(value)
                if pax:
                    member.pax_headers = {"mtime": "1.25"}
                archive.addfile(member, io.BytesIO(value))

    def test_normalizer_budget_failures_precede_tar_parser_and_preserve_input(self):
        cases = (
            ("MAX_COMPRESSED_BYTES", 1, [b"abc"]),
            ("MAX_RAW_TAR_BYTES", 1024, [b"x" * 4096]),
            ("MAX_MEMBER_BYTES", 16, [b"x" * 32]),
            ("MAX_TOTAL_BYTES", 32, [b"x" * 20, b"y" * 20]),
            ("MAX_MEMBERS", 1, [b"a", b"b"]),
        )
        for constant, budget, values in cases:
            with (
                self.subTest(constant=constant),
                tempfile.TemporaryDirectory() as directory,
            ):
                path = Path(directory) / "test.tar.gz"
                self.make_tar(path, values)
                original = path.read_bytes()
                with (
                    patch.object(normalizer.limits, constant, budget),
                    patch.object(
                        normalizer.tarfile,
                        "open",
                        side_effect=AssertionError(
                            "TAR parser ran before resource refusal"
                        ),
                    ),
                    self.assertRaises(normalizer.SdistNormalizationError),
                ):
                    normalizer.normalize_sdist(path, 0)
                self.assertEqual(original, path.read_bytes())
                self.assertEqual(list(path.parent.iterdir()), [path])

    def test_tar_pax_budget_truncation_and_trailing_streams_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pax.tar.gz"
            self.make_tar(path, [b"abc"], pax=True)
            original = path.read_bytes()
            with (
                patch.object(normalizer.limits, "MAX_METADATA_BYTES", 1),
                self.assertRaises(normalizer.SdistNormalizationError),
            ):
                normalizer.normalize_sdist(path, 0)
            for value in (original[:-1], original + gzip.compress(b"extra")):
                path.write_bytes(value)
                with self.assertRaises(normalizer.SdistNormalizationError):
                    normalizer.normalize_sdist(path, 0)
                self.assertEqual(path.read_bytes(), value)

    def test_normalizer_streams_bodies_and_accepts_bounded_fractional_pax(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "valid.tar.gz"
            self.make_tar(path, [b"x" * 70000, b"second"], pax=True)
            sizes = []
            original = tarfile.ExFileObject.read

            def read(stream, size=-1):
                self.assertGreaterEqual(size, 0)
                self.assertLessEqual(size, normalizer.limits.CHUNK_BYTES)
                sizes.append(size)
                return original(stream, size)

            with patch.object(tarfile.ExFileObject, "read", read):
                digest = normalizer.normalize_sdist(path, 0)
            self.assertTrue(sizes)
            self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(digest, normalizer.normalize_sdist(path, 0))

    def test_wheel_budget_and_method_failures_precede_zip_parser(self):
        cases = (
            ("MAX_COMPRESSED_BYTES", 1, [b"abc"], zipfile.ZIP_STORED),
            ("MAX_MEMBER_BYTES", 16, [b"x" * 32], zipfile.ZIP_DEFLATED),
            ("MAX_TOTAL_BYTES", 32, [b"x" * 20, b"y" * 20], zipfile.ZIP_STORED),
            ("MAX_MEMBERS", 1, [b"a", b"b"], zipfile.ZIP_STORED),
            ("MAX_CENTRAL_BYTES", 1, [b"a"], zipfile.ZIP_STORED),
            ("MAX_RATIO", 1, [b"x" * 1000], zipfile.ZIP_DEFLATED),
            ("MAX_MEMBER_BYTES", 1024, [b"abc"], zipfile.ZIP_BZIP2),
        )
        for constant, budget, values, method in cases:
            with (
                self.subTest(constant=constant, method=method),
                tempfile.TemporaryDirectory() as directory,
            ):
                path = Path(directory) / "small.whl"
                with zipfile.ZipFile(path, "w", compression=method) as archive:
                    for index, value in enumerate(values):
                        archive.writestr(f"file{index}.txt", value)
                with (
                    patch.object(release.limits, constant, budget),
                    patch.object(
                        release.zipfile,
                        "ZipFile",
                        side_effect=AssertionError(
                            "ZIP parser ran before resource refusal"
                        ),
                    ),
                    self.assertRaises(release.ReleaseEvidenceError),
                ):
                    release.validate_wheel(
                        path, VERSION, [], snapshot=path.read_bytes()
                    )

    def test_declared_zip_count_multipart_zip64_and_trailing_bytes_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "small.whl"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("file.txt", b"abc")
            original = path.read_bytes()
            offset = original.rfind(b"PK\x05\x06")
            for field, value in ((4, 1), (8, 0xFFFF), (10, 2)):
                changed = bytearray(original)
                struct.pack_into("<H", changed, offset + field, value)
                with self.assertRaises(release.ReleaseEvidenceError):
                    release.validate_wheel(path, VERSION, [], snapshot=bytes(changed))
            with self.assertRaises(release.ReleaseEvidenceError):
                release.validate_wheel(
                    path, VERSION, [], snapshot=original + b"trailing"
                )


class CompleteWheelSourceTests(unittest.TestCase):
    def fixture(self, root):
        helper = release_fixtures.ReleaseEvidenceTests()
        helper.make_source(root)
        helper.make_distributions(root / "dist")
        return next((root / "dist").glob("*.whl"))

    def test_complete_container_variants_refused_on_prepare_and_handoff(self):
        cases = (
            "empty_directory",
            "directory_body",
            "executable_mode",
            "special_mode",
            "extra_field",
            "entry_comment",
            "archive_comment",
            "mixed_platform",
            "internal_attribute",
            "dos_attribute",
            "creator_version",
            "null_filename_suffix",
            "local_method",
            "local_flags",
            "local_crc",
            "local_compressed",
            "local_decoded",
            "local_name",
            "local_extra",
            "local_timestamp",
            "preamble",
            "matching_false_crc",
            "matching_false_size",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                wheel = self.fixture(root)
                assets = root / "assets"
                release.prepare_release_evidence(
                    root, root / "dist", assets, TAG, COMMIT
                )
                for path in (root / "dist").iterdir():
                    (assets / path.name).write_bytes(path.read_bytes())
                if case in {"empty_directory", "directory_body"}:
                    rewrite_wheel(
                        wheel,
                        {
                            "unreviewed-hidden/": b""
                            if case == "empty_directory"
                            else b"Synthetic payload."
                        },
                    )
                elif case.startswith("local_") or case in {
                    "preamble",
                    "matching_false_crc",
                    "matching_false_size",
                }:
                    value = bytearray(wheel.read_bytes())
                    central = value.find(b"PK\x01\x02")
                    local = struct.unpack_from("<I", value, central + 42)[0]
                    mutations = {
                        "local_method": (8, "<H", 12),
                        "local_flags": (6, "<H", 1),
                        "local_crc": (14, "<I", 0),
                        "local_compressed": (18, "<I", 0xFFFFFFFF),
                        "local_decoded": (22, "<I", 0xFFFFFFFF),
                        "local_extra": (28, "<H", 1),
                        "local_timestamp": (10, "<H", 1),
                    }
                    if case in mutations:
                        delta, format_string, number = mutations[case]
                        struct.pack_into(format_string, value, local + delta, number)
                    elif case == "local_name":
                        value[local + 30] ^= 1
                    elif case == "matching_false_crc":
                        struct.pack_into("<I", value, local + 14, 0)
                        struct.pack_into("<I", value, central + 16, 0)
                    elif case == "matching_false_size":
                        old_size = struct.unpack_from("<I", value, local + 22)[0]
                        struct.pack_into("<I", value, local + 22, old_size + 1)
                        struct.pack_into("<I", value, central + 24, old_size + 1)
                    else:
                        # A valid self-extracting preamble shifts every local and
                        # central offset; it remains outside the approved source.
                        for offset in range(central, len(value) - 45):
                            if value[offset : offset + 4] == b"PK\x01\x02":
                                position = struct.unpack_from("<I", value, offset + 42)[
                                    0
                                ]
                                struct.pack_into("<I", value, offset + 42, position + 1)
                        end = value.rfind(b"PK\x05\x06")
                        position = struct.unpack_from("<I", value, end + 16)[0]
                        struct.pack_into("<I", value, end + 16, position + 1)
                        value = bytearray(b"X") + value
                    wheel.write_bytes(value)
                else:
                    with zipfile.ZipFile(wheel) as archive:
                        entries = [
                            (member, archive.read(member))
                            for member in archive.infolist()
                        ]
                    first = entries[0][0]
                    if case == "executable_mode":
                        first.external_attr = 0o100777 << 16
                    elif case == "special_mode":
                        first.external_attr = 0o020644 << 16
                    elif case == "extra_field":
                        first.extra = b"\xca\xfe\x04\x00data"
                    elif case == "entry_comment":
                        first.comment = b"Synthetic unreviewed comment."
                    elif case == "mixed_platform":
                        first.create_system = 0
                        first.external_attr = 0o100666 << 16
                    elif case == "internal_attribute":
                        first.internal_attr = 1
                    elif case == "dos_attribute":
                        first.external_attr |= 1
                    elif case == "creator_version":
                        first.create_version = 21
                    elif case == "null_filename_suffix":
                        first.filename += "\0suffix"
                    with zipfile.ZipFile(wheel, "w") as archive:
                        for member, data in entries:
                            archive.writestr(member, data)
                        if case == "archive_comment":
                            archive.comment = b"Synthetic unreviewed archive comment."
                # Header-only changes preserve RECORD; added directory entries
                # above receive a freshly generated complete RECORD.
                with self.assertRaises(release.ReleaseEvidenceError):
                    release.prepare_release_evidence(
                        root, root / "dist", root / "refused", TAG, COMMIT
                    )
                self.assertFalse((root / "refused").exists())
                (assets / wheel.name).write_bytes(wheel.read_bytes())
                with self.assertRaises((RuntimeError, ValueError)):
                    handoff.verify_handoff(assets, root, COMMIT, TAG)

    def test_local_header_refusal_precedes_zipfile_and_platform_positives_hold(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = self.fixture(root)
            dependencies = release.parse_optional_dependencies(root)
            release.validate_wheel(wheel, VERSION, dependencies, root)
            original = wheel.read_bytes()
            for delta, format_string, number in (
                (8, "<H", 12),
                (6, "<H", 1),
                (22, "<I", 0xFFFFFFFF),
            ):
                value = bytearray(original)
                struct.pack_into(format_string, value, delta, number)
                with (
                    patch.object(
                        release.zipfile,
                        "ZipFile",
                        side_effect=AssertionError(
                            "ZIP parser ran before header refusal"
                        ),
                    ),
                    self.assertRaises(release.ReleaseEvidenceError),
                ):
                    release.validate_wheel(
                        wheel, VERSION, dependencies, root, snapshot=bytes(value)
                    )
            with zipfile.ZipFile(wheel) as archive:
                entries = [
                    (member, archive.read(member)) for member in archive.infolist()
                ]
            with zipfile.ZipFile(
                wheel, "w", compression=zipfile.ZIP_DEFLATED
            ) as archive:
                for member, value in entries:
                    member.create_system = 0
                    member.compress_type = zipfile.ZIP_DEFLATED
                    member.external_attr = (
                        0o100664 if member.filename.endswith("/RECORD") else 0o100666
                    ) << 16
                    archive.writestr(member, value)
            release.validate_wheel(wheel, VERSION, dependencies, root)

    def test_deflate_trailing_member_bytes_refused_with_consistent_header_sizes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = self.fixture(root)
            with zipfile.ZipFile(wheel) as archive:
                entries = [
                    (member, archive.read(member)) for member in archive.infolist()
                ]
            with zipfile.ZipFile(wheel, "w") as archive:
                for member, data in entries:
                    member.compress_type = zipfile.ZIP_DEFLATED
                    archive.writestr(member, data)
            release.validate_wheel(
                wheel, VERSION, release.parse_optional_dependencies(root), root
            )
            original = wheel.read_bytes()
            value = bytearray(original)
            central = value.find(b"PK\x01\x02")
            local = struct.unpack_from("<I", value, central + 42)[0]
            compressed = struct.unpack_from("<I", value, central + 20)[0]
            name, extra = struct.unpack_from("<HH", value, local + 26)
            following = local + 30 + name + extra + compressed
            struct.pack_into("<I", value, local + 18, compressed + 1)
            struct.pack_into("<I", value, central + 20, compressed + 1)
            for offset in range(central, len(value) - 45):
                if value[offset : offset + 4] == b"PK\x01\x02":
                    position = struct.unpack_from("<I", value, offset + 42)[0]
                    if position > local:
                        struct.pack_into("<I", value, offset + 42, position + 1)
            end = value.rfind(b"PK\x05\x06")
            struct.pack_into("<I", value, end + 16, central + 1)
            value[following:following] = b"X"
            with (
                patch.object(
                    release.zipfile,
                    "ZipFile",
                    side_effect=AssertionError("ZIP parser ran before stream refusal"),
                ),
                self.assertRaisesRegex(release.ReleaseEvidenceError, "trailing data"),
            ):
                release.validate_wheel(wheel, VERSION, [], root, snapshot=bytes(value))

    def test_self_consistent_metadata_variants_refused_on_prepare_and_trusted_handoff(
        self,
    ):
        prefix = f"bedrock_guardrail_firewall-{VERSION}.dist-info/"
        for case in (
            "url",
            "body",
            "author",
            "classifier",
            "WHEEL",
            "top_level.txt",
            "entry_points.txt",
            "licenses/LICENSE",
            "licenses/NOTICE",
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                wheel = self.fixture(root)
                assets = root / "assets"
                release.prepare_release_evidence(
                    root, root / "dist", assets, TAG, COMMIT
                )
                for path in (root / "dist").iterdir():
                    (assets / path.name).write_bytes(path.read_bytes())
                with zipfile.ZipFile(wheel) as archive:
                    metadata = archive.read(prefix + "METADATA")
                if case == "body":
                    changes = {
                        prefix + "METADATA": metadata.replace(
                            b"Synthetic package description.",
                            b"Source divergent description.",
                        )
                    }
                elif case in {"url", "author", "classifier"}:
                    field = {
                        "url": b"Project-URL: Homepage, https://example.invalid/unreviewed\n",
                        "author": b"Author: Synthetic author\n",
                        "classifier": b"Classifier: Synthetic alternate\n",
                    }[case]
                    changes = {prefix + "METADATA": field + metadata}
                else:
                    changes = {prefix + case: b"Source divergent synthetic metadata\n"}
                rewrite_wheel(wheel, changes)
                # Fresh RECORD proves source binding rather than a stale hash.
                with self.assertRaises(release.ReleaseEvidenceError):
                    release.prepare_release_evidence(
                        root, root / "dist", root / "rejected", TAG, COMMIT
                    )
                (assets / wheel.name).write_bytes(wheel.read_bytes())
                with self.assertRaisesRegex(RuntimeError, "Wheel"):
                    handoff.verify_handoff(assets, root, COMMIT, TAG)

    def test_declared_license_bytes_are_authenticated_not_only_allowed_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = self.fixture(root)
            project = root / "pyproject.toml"
            project.write_text(
                project.read_text().replace(
                    "license-files = []", 'license-files = ["LICENSE", "NOTICE"]'
                )
            )
            manifest = root / "MANIFEST.in"
            manifest.write_text(manifest.read_text() + "include LICENSE NOTICE\n")
            (root / "LICENSE").write_bytes(b"Synthetic source license bytes.\n")
            (root / "NOTICE").write_bytes(b"Synthetic source notice bytes.\n")
            prefix = f"bedrock_guardrail_firewall-{VERSION}.dist-info/"
            expected = release.reviewed_wheel_members(root, VERSION)
            rewrite_wheel(
                wheel, {name: next(iter(values)) for name, values in expected.items()}
            )
            dependencies = release.parse_optional_dependencies(root)
            release.validate_wheel(wheel, VERSION, dependencies, root)
            for name in ("LICENSE", "NOTICE"):
                member = prefix + "licenses/" + name
                correct = (root / name).read_bytes()
                rewrite_wheel(wheel, {member: b"Unreviewed synthetic replacement.\n"})
                with self.assertRaisesRegex(
                    release.ReleaseEvidenceError, "differs from reviewed source"
                ):
                    release.validate_wheel(wheel, VERSION, dependencies, root)
                rewrite_wheel(wheel, {member: correct})

    def test_all_metadata_required_exact_source_license_bytes_and_platform_newlines(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = self.fixture(root)
            dependencies = release.parse_optional_dependencies(root)
            release.validate_wheel(wheel, VERSION, dependencies, root)
            prefix = f"bedrock_guardrail_firewall-{VERSION}.dist-info/"
            with zipfile.ZipFile(wheel) as archive:
                metadata = archive.read(prefix + "METADATA")
            rewrite_wheel(
                wheel, {prefix + "METADATA": metadata.replace(b"\n", b"\r\n")}
            )
            release.validate_wheel(wheel, VERSION, dependencies, root)
            with zipfile.ZipFile(wheel) as archive:
                values = {
                    name: archive.read(name)
                    for name in archive.namelist()
                    if not name.endswith("/WHEEL")
                }
            with zipfile.ZipFile(wheel, "w") as archive:
                for name, value in values.items():
                    archive.writestr(release_fixtures.canonical_wheel_info(name), value)
            with self.assertRaisesRegex(release.ReleaseEvidenceError, "exact reviewed"):
                release.validate_wheel(wheel, VERSION, dependencies, root)
