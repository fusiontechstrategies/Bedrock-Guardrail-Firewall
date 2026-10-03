from __future__ import annotations

import base64
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from types import SimpleNamespace
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import orchestrator as app
from scripts import prepare_release_evidence as release
from tests.test_orchestrator import FakeBedrockClient, GuardrailTestCase
from tests import test_release_evidence as release_tests

VERSION = release_tests.VERSION


class CompletePrivateKeyTests(GuardrailTestCase):
    def key(self, label="PRIVATE KEY"):
        body = base64.b64encode(
            b"synthetic non-key material for boundary testing"
        ).decode()
        return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----", body

    def test_complete_custom_sanitization_covers_each_route_and_key_label(self):
        for label in (
            "PRIVATE KEY",
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
            "PGP PRIVATE KEY BLOCK",
        ):
            for route in ("input", "output", "retrieval"):
                with self.subTest(label=label, route=route):
                    key, body = self.key(label)
                    client = FakeBedrockClient()
                    system = self.make_live_system(client)
                    system.privacy.bundle = replace(
                        system.bundle,
                        entity_actions={
                            **system.bundle.entity_actions,
                            "PRIVATE_KEY": app.GuardrailAction.SANITIZE,
                        },
                    )
                    text = "A safe summary."
                    context = {
                        "retrieval_contexts": [{"id": "synthetic", "text": text}]
                    }
                    user, output = text, text
                    if route == "input":
                        user += " " + key
                    elif route == "output":
                        output += " " + key
                    else:
                        context["retrieval_contexts"][0]["text"] += " " + key
                    result = system.process(user, context, output, record=False)
                    self.assertTrue(result["content_released"])
                    self.assertTrue(client.calls)
                    for rendered in (json.dumps(result), json.dumps(client.calls)):
                        self.assertNotIn(body, rendered)
                        self.assertNotIn("BEGIN " + label, rendered)
                        self.assertNotIn("END " + label, rendered)

    def test_unmapped_or_explicit_allow_keys_are_blocked(self):
        for action in (None, app.GuardrailAction.ALLOW):
            client = FakeBedrockClient()
            system = self.make_live_system(client)
            actions = dict(system.bundle.entity_actions)
            if action is None:
                actions.pop("PRIVATE_KEY", None)
            else:
                actions["PRIVATE_KEY"] = action
            system.privacy.bundle = replace(system.bundle, entity_actions=actions)
            result = system.process(self.key()[0], {}, record=False)
            self.assertEqual(result["recommended_action"], "block")
            self.assertFalse(result["content_released"])
            self.assertFalse(client.calls)

    def test_incomplete_mismatched_nested_and_oversized_keys_fail_closed(self):
        key, _ = self.key()
        for malformed in (
            key.split("-----END")[0],
            key.replace("END PRIVATE", "END RSA PRIVATE"),
            key.replace("\n", "\n-----BEGIN EC PRIVATE KEY-----\n", 1),
            key.replace("\n", "\n" + "A" * 16385, 1),
        ):
            with self.subTest(length=len(malformed)):
                client = FakeBedrockClient()
                system = self.make_live_system(client)
                system.privacy.bundle = replace(
                    system.bundle,
                    entity_actions={
                        **system.bundle.entity_actions,
                        "PRIVATE_KEY": app.GuardrailAction.SANITIZE,
                    },
                )
                result = system.process(malformed, {}, record=False)
                self.assertEqual(result["recommended_action"], "block")
                self.assertFalse(result["content_released"])
                self.assertFalse(client.calls)

    def test_adjacent_keys_and_body_personal_data_leave_no_tail(self):
        system = self.make_system()
        system.privacy.bundle = replace(
            system.bundle,
            entity_actions={
                **system.bundle.entity_actions,
                "PRIVATE_KEY": app.GuardrailAction.SANITIZE,
            },
        )
        first, body = self.key()
        second = first.replace(body, "synthetic@example.invalid")
        result = system.process(
            "before " + first + " " + second + " after", {}, record=False
        )
        self.assertNotIn(body, json.dumps(result))
        self.assertNotIn("synthetic@example.invalid", json.dumps(result))
        self.assertEqual(result["recommended_action"], "block")
        self.assertFalse(result["content_released"])

    def test_premature_footer_empty_body_and_orphan_footer_block_every_route(self):
        key, body = self.key()
        begin, end = key.splitlines()[0], key.splitlines()[-1]
        variants = (
            begin + "\n" + end + "\n" + body + "\n" + end,
            key + "\n" + body + "\n" + end,
            begin + "\n" + end,
            body + "\n" + end,
        )
        for text in variants:
            for route in ("input", "output", "retrieval"):
                with self.subTest(route=route, text=text[:25]):
                    client = FakeBedrockClient()
                    system = self.make_live_system(client)
                    system.privacy.bundle = replace(
                        system.bundle,
                        entity_actions={
                            **system.bundle.entity_actions,
                            "PRIVATE_KEY": app.GuardrailAction.SANITIZE,
                        },
                    )
                    user, output, context = "A safe summary.", "A safe summary.", {}
                    if route == "input":
                        user = text
                    elif route == "output":
                        output = text
                    else:
                        context = {
                            "retrieval_contexts": [{"id": "synthetic", "text": text}]
                        }
                    result = system.process(user, context, output, record=False)
                    self.assertEqual(result["recommended_action"], "block")
                    self.assertFalse(result["content_released"])
                    self.assertFalse(client.calls)

    def test_valid_decoy_footerless_key_continuation_blocks_all_routes(self):
        begin, end = self.key()[0].splitlines()[::2]
        tail = base64.b64encode(
            b"\x30\x82\x01\x00" + b"synthetic-not-a-real-key" * 24
        ).decode()
        for separator in ("\n", " ", "\t\r\n"):
            text = begin + "\nQQ==\n" + end + separator + tail
            for route in ("input", "output", "retrieval"):
                with self.subTest(separator=repr(separator), route=route):
                    client = FakeBedrockClient()
                    system = self.make_live_system(client)
                    system.privacy.bundle = replace(
                        system.bundle,
                        entity_actions={
                            **system.bundle.entity_actions,
                            "PRIVATE_KEY": app.GuardrailAction.SANITIZE,
                        },
                    )
                    if route == "input":
                        result = system.process(text, {}, record=False)
                    elif route == "output":
                        result = system.process("safe", {}, text, record=False)
                    else:
                        result = system.process(
                            "safe",
                            {"retrieval_contexts": [{"id": "synthetic", "text": text}]},
                            record=False,
                        )
                    self.assertEqual(result["recommended_action"], "block")
                    self.assertFalse(result["content_released"])
                    self.assertFalse(client.calls)
                    self.assertNotIn(tail, json.dumps(result))


class BoundedJsonTests(unittest.TestCase):
    def test_limit_and_utf8_duplicate_depth_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_bytes(b'{"a":1}')
            self.assertEqual(app._load_json_file(path, maximum_bytes=7), {"a": 1})
            with self.assertRaises(app.ConfigurationError):
                app._load_json_file(path, maximum_bytes=6)
            for raw in (b"\xff", b'{"a":1,"a":2}', b"[" * 40 + b"0" + b"]" * 40):
                path.write_bytes(raw)
                with self.assertRaises(app.ConfigurationError):
                    app._load_json_file(path)

    def test_growth_after_fstat_consumes_at_most_limit_plus_one(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "growing.json"
            path.write_bytes(b" " * 100000)
            real_fstat = os.fstat
            real_fdopen = os.fdopen
            reads = []

            class Reader:
                def __init__(self, handle):
                    self.handle = handle

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    self.handle.close()

                def fileno(self):
                    return self.handle.fileno()

                def read(self, size):
                    value = self.handle.read(size)
                    reads.append((size, len(value)))
                    return value

            def small_info(fd):
                info = real_fstat(fd)
                return SimpleNamespace(
                    st_mode=info.st_mode,
                    st_size=0,
                    st_file_attributes=getattr(info, "st_file_attributes", 0),
                )

            with (
                patch.object(app.os, "fstat", side_effect=small_info),
                patch.object(
                    app.os,
                    "fdopen",
                    side_effect=lambda fd, mode: Reader(real_fdopen(fd, mode)),
                ),
                self.assertRaises(app.ConfigurationError),
            ):
                app._load_json_file(path, maximum_bytes=32)
            self.assertEqual(reads, [(33, 33)])

    def test_path_replacement_after_open_does_not_change_selected_bytes(self):
        if os.name == "nt":
            # The Windows descriptor also denies delete sharing, preventing this swap.
            return
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_bytes(b'{"old":true}')
            opener = app._open_json_read

            def swapped(path):
                fd = opener(path)
                path.unlink()
                path.write_bytes(b'{"new":true}')
                return fd

            with patch.object(app, "_open_json_read", side_effect=swapped):
                self.assertEqual(app._load_json_file(path), {"old": True})

    @unittest.skipIf(os.name == "nt", "POSIX relative descriptor traversal regression")
    def test_intermediate_link_swap_after_lstat_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            namespace, alternate = root / "namespace", root / "alternate"
            namespace.mkdir()
            alternate.mkdir()
            (namespace / "input.json").write_text('{"selected":true}')
            (alternate / "input.json").write_text('{"alternate":true}')
            check = app._reject_path_links

            def swap(path):
                check(path)
                namespace.rename(root / "old")
                namespace.symlink_to(alternate, target_is_directory=True)

            with (
                patch.object(app, "_reject_path_links", side_effect=swap),
                self.assertRaises(app.ConfigurationError),
            ):
                app._load_json_file(namespace / "input.json")

    @unittest.skipUnless(os.name == "nt", "Windows reparse traversal regression")
    def test_windows_intermediate_link_swap_after_lstat_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            namespace, alternate = root / "namespace", root / "alternate"
            namespace.mkdir()
            alternate.mkdir()
            (namespace / "input.json").write_text('{"selected":true}')
            (alternate / "input.json").write_text('{"alternate":true}')
            check = app._reject_path_links

            def swap(path):
                check(path)
                namespace.rename(root / "old")
                try:
                    namespace.symlink_to(alternate, target_is_directory=True)
                except OSError as error:
                    self.skipTest(
                        f"Directory symlink creation unavailable: {error.winerror}"
                    )

            with (
                patch.object(app, "_reject_path_links", side_effect=swap),
                self.assertRaises(app.ConfigurationError),
            ):
                app._load_json_file(namespace / "input.json")

    @unittest.skipUnless(os.name == "nt", "Windows namespace pin regression")
    def test_windows_parent_replacement_cannot_redirect_relative_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            namespace = root / "namespace"
            namespace.mkdir()
            path = namespace / "input.json"
            path.write_text('{"selected":true}')
            opener = app._windows_relative_open
            swapped = False

            def swapped_open(name, handle, **kwargs):
                nonlocal swapped
                if name == "input.json" and not swapped:
                    swapped = True
                    try:
                        namespace.rename(root / "moved")
                    except PermissionError:
                        pass  # The retained native handle denies namespace deletion.
                    else:
                        namespace.mkdir()
                        path.write_text('{"alternate":true}')
                return opener(name, handle, **kwargs)

            with patch.object(app, "_windows_relative_open", side_effect=swapped_open):
                self.assertEqual(app._load_json_file(path), {"selected": True})
            self.assertTrue(swapped)
            self.assertEqual(
                app._load_json_file(path),
                {"alternate": True}
                if (root / "moved").exists()
                else {"selected": True},
            )

    @unittest.skipIf(os.name == "nt", "POSIX FIFO regression")
    def test_fifo_is_rejected_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pipe"
            os.mkfifo(path)
            start = time.monotonic()
            with self.assertRaises(app.ConfigurationError):
                app._load_json_file(path)
            self.assertLess(time.monotonic() - start, 1)

    def test_json_symlink_and_directory_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_text("{}")
            with self.assertRaises(app.ConfigurationError):
                app._load_json_file(root)
            link = root / "link.json"
            try:
                link.symlink_to(target)
            except OSError:
                return
            with self.assertRaises(app.ConfigurationError):
                app._load_json_file(link)


class UnicodeRegexTests(unittest.TestCase):
    def test_runtime_unicode_case_collisions_are_rejected(self):
        for left, right in (
            ("I", "ı"),
            ("I", "İ"),
            ("s", "ſ"),
            ("k", "K"),
            ("[A-Z]", "ı"),
            ("[^i]", "x"),
        ):
            for separator in ("", left):
                pattern = f"{left}{{0,80}}{separator}{right}{{0,80}}Z"
                with (
                    self.subTest(pattern=pattern),
                    self.assertRaises(app.ConfigurationError),
                ):
                    app._validate_safe_pattern(pattern, "synthetic")

    @unittest.skipIf(
        sys.version_info < (3, 11), "Atomic syntax introduced in Python3.11"
    )
    def test_atomic_group_cannot_hide_competing_repetitions(self):
        for pattern in (
            r"(?>a{0,256}a{0,256}a{0,256}a{0,256}X)",
            r"(?>I{0,100}\u0131{0,100}X)",
        ):
            with self.assertRaises(app.ConfigurationError):
                app._validate_safe_pattern(pattern, "synthetic")

    def test_scoped_flags_rejected_and_disjoint_ascii_and_policies_pass(self):
        with self.assertRaises(app.ConfigurationError):
            app._validate_safe_pattern(r"a{0,80}(?-i:A{0,80})Z", "synthetic")
        for pattern in (r"a{0,80}b{0,80}Z", r"[0-9]{0,80}[a-z]{0,80}Z"):
            self.assertEqual(app._validate_safe_pattern(pattern, "synthetic"), pattern)
        root = Path(__file__).resolve().parents[1]
        app.load_policy_bundle(
            root / "guardrail_policy.json", root / "guardrail_policy_profiles.json"
        )


class AuxiliaryFileTests(GuardrailTestCase):
    def test_hardlinks_and_existing_probe_are_never_written(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "untouched"
            target.write_bytes(b"unchanged")
            locks = root / "locks"
            fd = app._open_private_key(locks, create=True, directory=True)
            os.close(fd)
            lock = locks / "state.lock"
            os.link(target, lock)
            with (
                self.assertRaises((app.ConfigurationError, app.StorageError, OSError)),
                app.CrossProcessFileLock(lock),
            ):
                self.fail("hardlinked lock acquired")
            self.assertEqual(target.read_bytes(), b"unchanged")
            with self.assertRaises(app.StorageError):
                app._write_restricted(lock, b"changed")
            self.assertEqual(target.read_bytes(), b"unchanged")
        system = self.make_system()
        legacy = system.config.data_dir / ".write-probe"
        legacy.write_bytes(b"leave me alone")
        self.assertTrue(
            next(x for x in system.doctor()["checks"] if x["name"] == "data_directory")[
                "status"
            ]
            == "pass"
        )
        self.assertEqual(legacy.read_bytes(), b"leave me alone")
        self.assertFalse(
            list((system.config.data_dir / "locks").glob(".write-probe-*"))
        )

    def test_auxiliary_symlink_target_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            locks = root / "locks"
            fd = app._open_private_key(locks, create=True, directory=True)
            os.close(fd)
            target = root / "untouched"
            target.write_bytes(b"unchanged")
            link = locks / "state.lock"
            try:
                link.symlink_to(target)
            except OSError:
                return
            with (
                self.assertRaises((app.ConfigurationError, app.StorageError, OSError)),
                app.CrossProcessFileLock(link),
            ):
                self.fail("linked lock acquired")
            self.assertEqual(target.read_bytes(), b"unchanged")

    def test_cross_process_lock_preserves_mutual_exclusion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "locks" / "state.lock"
            marker = root / "acquired"
            code = (
                "import sys; from pathlib import Path; import orchestrator as a; "
                "p=Path(sys.argv[1]); "
                "\nwith a.CrossProcessFileLock(p): "
                "Path(sys.argv[2]).write_text('acquired')"
            )
            with app.CrossProcessFileLock(lock):
                proc = subprocess.Popen(
                    [sys.executable, "-c", code, str(lock), str(marker)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                try:
                    time.sleep(0.2)
                    self.assertFalse(marker.exists())
                    self.assertIsNone(proc.poll())
                except BaseException:
                    proc.kill()
                    proc.wait()
                    raise
            stdout, stderr = proc.communicate(timeout=10)
            self.assertEqual(proc.returncode, 0, (stdout, stderr))
            self.assertEqual(marker.read_text(), "acquired")

    @unittest.skipIf(os.name == "nt", "POSIX ancestor namespace regression")
    def test_world_writable_nonsticky_ancestor_rejected_before_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ancestor = root / "ancestor"
            ancestor.mkdir()
            data = ancestor / "data"
            data.mkdir(mode=0o700)
            ancestor.chmod(0o777)
            try:
                with (
                    self.assertRaises(app.StorageError),
                    app.CrossProcessFileLock(data / "locks" / "state.lock"),
                ):
                    self.fail("unsafe ancestor dispatch")
            finally:
                ancestor.chmod(0o700)

    @unittest.skipIf(os.name == "nt", "POSIX root-relative lock namespace regression")
    def test_root_rename_during_child_open_does_not_select_another_namespace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "data"
            data.mkdir(mode=0o700)
            moved = root / "moved"
            original = app._open_private_key
            seen = []

            def swap(path, **kwargs):
                if (
                    kwargs.get("directory")
                    and kwargs.get("create")
                    and path.name == "locks"
                ):
                    data.rename(moved)
                    data.mkdir(mode=0o700)
                    seen.append(True)
                return original(path, **kwargs)

            with (
                patch.object(app, "_open_private_key", side_effect=swap),
                app.CrossProcessFileLock(data / "locks" / "state.lock"),
            ):
                self.assertTrue((moved / "locks" / "state.lock").exists())
                self.assertFalse((data / "locks").exists())
            self.assertEqual(seen, [True])

    @unittest.skipUnless(os.name == "nt", "Windows synthetic namespace ACL regression")
    def test_other_principal_writable_parent_rejected_before_lock_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = subprocess.run(
                ["icacls", str(root), "/grant", "*S-1-1-0:(OI)(CI)F"],
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0)
            lock = root / "locks" / "state.lock"
            with (
                self.assertRaises(app.ConfigurationError),
                app.CrossProcessFileLock(lock),
            ):
                self.fail("other-principal-writable namespace acquired")
            self.assertFalse(lock.exists())

    @unittest.skipIf(os.name == "nt", "POSIX owner/mode regression")
    def test_unsafe_parent_modes_and_fifo_locks_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            locks = root / "locks"
            locks.mkdir(mode=0o700)
            lock = locks / "fifo.lock"
            os.mkfifo(lock, 0o600)
            with self.assertRaises(app.StorageError), app.CrossProcessFileLock(lock):
                self.fail("FIFO acquired")
            root.chmod(0o777)
            try:
                with (
                    self.assertRaises(app.StorageError),
                    app.CrossProcessFileLock(locks / "state.lock"),
                ):
                    self.fail("unsafe namespace acquired")
            finally:
                root.chmod(0o700)


class CompleteSdistTests(unittest.TestCase):
    def fixture(self, root):
        builder = release_tests.ReleaseEvidenceTests()
        builder.make_source(root)
        for name in (
            "docs/guide.md",
            "examples/demo.json",
            "tests/test_demo.py",
            "requirements-build.lock",
        ):
            path = root / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(b"synthetic reviewed bytes\n")
        manifest = root / "MANIFEST.in"
        manifest.write_text(
            manifest.read_text()
            + "include requirements*.lock\nrecursive-include docs *.md\n"
            "recursive-include examples *.json\nrecursive-include tests *.py\n"
        )
        builder.make_distributions(root / "dist")
        return next((root / "dist").glob("*.tar.gz"))

    def change(self, archive_path, selected, *, remove=False, add=False):
        with tarfile.open(archive_path, "r:gz") as archive:
            entries = [
                (m, archive.extractfile(m).read() if m.isfile() else None)
                for m in archive.getmembers()
            ]
        with tarfile.open(archive_path, "w:gz") as archive:
            for member, value in entries:
                if member.name.endswith("/" + selected):
                    if remove:
                        continue
                    value += b"unreviewed"
                    member.size = len(value)
                archive.addfile(
                    member, io.BytesIO(value) if value is not None else None
                )
            if add:
                value = b"unreviewed"
                member = tarfile.TarInfo(
                    f"bedrock_guardrail_firewall-{VERSION}/unreviewed.md"
                )
                member.size = len(value)
                archive.addfile(member, io.BytesIO(value))

    def test_every_source_type_and_generated_metadata_is_authenticated(self):
        for name in (
            "README.md",
            "CHANGELOG.md",
            "requirements-aws.txt",
            "requirements-build.lock",
            "docs/guide.md",
            "examples/demo.json",
            "tests/test_demo.py",
            "scripts/validate_installed_package.py",
            "guardrail_policy.json",
            "orchestrator.py",
            "MANIFEST.in",
            "PKG-INFO",
            "setup.cfg",
            "bedrock_guardrail_firewall.egg-info/SOURCES.txt",
            "bedrock_guardrail_firewall.egg-info/requires.txt",
            "bedrock_guardrail_firewall.egg-info/entry_points.txt",
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = self.fixture(root)
                release.validate_sdist(archive, VERSION, root)
                self.change(archive, name)
                with self.assertRaises(release.ReleaseEvidenceError):
                    release.validate_sdist(archive, VERSION, root)

    def test_extra_or_missing_source_or_metadata_is_rejected(self):
        for selected, remove, add in (
            ("README.md", True, False),
            ("bedrock_guardrail_firewall.egg-info/PKG-INFO", True, False),
            ("nothing", False, True),
        ):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = self.fixture(root)
                self.change(archive, selected, remove=remove, add=add)
                with self.assertRaises(release.ReleaseEvidenceError):
                    release.validate_sdist(archive, VERSION, root)

    def test_unapproved_pax_and_concatenated_gzip_are_rejected(self):
        import gzip

        for mode in ("pax", "concatenated", "trailing_tar", "comment"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive_path = self.fixture(root)
                if mode == "pax":
                    with tarfile.open(archive_path, "r:gz") as archive:
                        entries = [
                            (m, archive.extractfile(m).read() if m.isfile() else None)
                            for m in archive
                        ]
                    entries[0][0].pax_headers["SCHILY.xattr.synthetic"] = "unreviewed"
                    with tarfile.open(archive_path, "w:gz") as archive:
                        for member, value in entries:
                            archive.addfile(
                                member, io.BytesIO(value) if value is not None else None
                            )
                elif mode == "concatenated":
                    archive_path.write_bytes(
                        archive_path.read_bytes() + gzip.compress(b"unreviewed")
                    )
                elif mode == "trailing_tar":
                    raw = gzip.decompress(archive_path.read_bytes())
                    archive_path.write_bytes(gzip.compress(raw + b"unreviewed"))
                else:
                    raw = bytearray(archive_path.read_bytes())
                    raw[3] |= 16
                    archive_path.write_bytes(raw)
                with self.assertRaises(release.ReleaseEvidenceError):
                    release.validate_sdist(archive_path, VERSION, root)

    def test_noncanonical_tar_ownership_timestamp_and_modes_are_rejected(self):
        for field, value in (
            ("uid", 1001),
            ("gid", 1001),
            ("uname", "other-user"),
            ("gname", "other-group"),
            ("mtime", 1),
            ("mode", 0o666),
            ("directory_mode", 0o777),
            ("pax_headers", {"mtime": "1.5"}),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = self.fixture(root)
                release.validate_sdist(path, VERSION, root)
                with tarfile.open(path, "r:gz") as archive:
                    entries = [
                        (m, archive.extractfile(m).read() if m.isfile() else None)
                        for m in archive
                    ]
                if field == "directory_mode":
                    member = tarfile.TarInfo(
                        f"bedrock_guardrail_firewall-{VERSION}/docs"
                    )
                    member.type, member.mode = tarfile.DIRTYPE, value
                    entries.append((member, None))
                else:
                    setattr(entries[0][0], field, value)
                with tarfile.open(path, "w:gz") as archive:
                    for member, data in entries:
                        archive.addfile(
                            member, io.BytesIO(data) if data is not None else None
                        )
                with self.assertRaises(release.ReleaseEvidenceError):
                    release.validate_sdist(path, VERSION, root)

    def test_artifact_replacement_after_validation_never_receives_evidence(self):
        from tests.test_release_evidence import TAG, COMMIT

        for boundary in ("wheel", "sdist"):
            with (
                self.subTest(boundary=boundary),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                archive_path = self.fixture(root)
                original = (
                    release.validate_wheel
                    if boundary == "wheel"
                    else release.validate_sdist
                )
                target = (
                    next((root / "dist").glob("*.whl"))
                    if boundary == "wheel"
                    else archive_path
                )

                def replace_after(*args, original=original, target=target, **kwargs):
                    result = original(*args, **kwargs)
                    target.unlink()
                    target.write_bytes(b"never validated")
                    return result

                with (
                    patch.object(
                        release, "validate_" + boundary, side_effect=replace_after
                    ),
                    self.assertRaisesRegex(release.ReleaseEvidenceError, "changed"),
                ):
                    release.prepare_release_evidence(
                        root, root / "dist", root / "evidence", TAG, COMMIT
                    )
                self.assertFalse((root / "evidence").exists())

    def test_manifest_cannot_execute_or_import_build_hooks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self.fixture(root)
            (root / "MANIFEST.in").write_text("global-include *\n")
            with self.assertRaises(release.ReleaseEvidenceError):
                release.validate_sdist(archive, VERSION, root)


if __name__ == "__main__":
    unittest.main()
