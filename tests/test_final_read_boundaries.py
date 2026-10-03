from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import orchestrator as app
from tests import test_orchestrator as fixtures

ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_REDIRECTED_TEXT = "Synthetic protected matching-name message."


def replace_directory_with_link(path, destination):
    path.rename(path.with_name(path.name + "-original"))
    if os.name == "nt":
        result = subprocess.run(
            ["cmd.exe", "/c", "mklink", "/J", str(path), str(destination)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
    else:
        path.symlink_to(destination, target_is_directory=True)


def remove_link(path):
    if os.name == "nt":
        path.rmdir()
    else:
        path.unlink()


class CliReadBoundaryTests(unittest.TestCase):
    def test_public_evaluate_parent_pin_preserves_original_file_or_refuses_swap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            requested, protected = root / "requested", root / "protected"
            requested.mkdir()
            protected.mkdir()
            path = requested / "input.txt"
            path.write_text("A safe requested message.", encoding="utf-8")
            (protected / path.name).write_text(
                SYNTHETIC_REDIRECTED_TEXT, encoding="utf-8"
            )
            swapped, attempted = False, False
            opener = app._windows_relative_open if os.name == "nt" else app.os.open

            def race(name, *args, **kwargs):
                nonlocal swapped, attempted
                if name == path.name and not attempted:
                    attempted = True
                    try:
                        replace_directory_with_link(requested, protected)
                        swapped = True
                    except PermissionError:
                        # Retained Windows handles deny deletion of the pinned parent.
                        pass
                return opener(name, *args, **kwargs)

            target = "_windows_relative_open" if os.name == "nt" else "open"
            owner = app if os.name == "nt" else app.os
            stdout = io.StringIO()
            try:
                with (
                    patch.object(owner, target, side_effect=race),
                    patch.object(
                        app.PrivacyKey,
                        "_load_or_create",
                        return_value=fixtures.TEST_KEY,
                    ),
                    patch("sys.stdout", stdout),
                ):
                    code = app.main(
                        [
                            "--policy",
                            str(fixtures.POLICY_PATH),
                            "--profiles",
                            str(fixtures.PROFILES_PATH),
                            "--data-dir",
                            str(root / "state"),
                            "--presidio-mode",
                            "disabled",
                            "evaluate",
                            "--no-record",
                            "--input-file",
                            str(path),
                        ]
                    )
                self.assertTrue(attempted)
                self.assertEqual(code, app.EXIT_OK)
                self.assertEqual(
                    json.loads(stdout.getvalue())["sanitized_input"],
                    "A safe requested message.",
                )
                self.assertNotIn(SYNTHETIC_REDIRECTED_TEXT, stdout.getvalue())
            finally:
                if swapped:
                    remove_link(requested)

    def test_public_evaluate_directory_swap_never_releases_redirected_text(self):
        for option in ("--input-file", "--candidate-output-file"):
            with (
                self.subTest(option=option),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory).resolve()
                requested, protected = root / "requested", root / "protected"
                requested.mkdir()
                protected.mkdir()
                path = requested / "input.txt"
                path.write_text("A safe requested message.", encoding="utf-8")
                (protected / path.name).write_text(
                    SYNTHETIC_REDIRECTED_TEXT, encoding="utf-8"
                )
                original = app._reject_path_links
                swapped = False

                def race(
                    checked,
                    original=original,
                    path=path,
                    requested=requested,
                    protected=protected,
                ):
                    nonlocal swapped
                    original(checked)
                    if Path(checked) == path and not swapped:
                        replace_directory_with_link(requested, protected)
                        swapped = True

                stdout, stderr = io.StringIO(), io.StringIO()
                args = [
                    "--policy",
                    str(fixtures.POLICY_PATH),
                    "--profiles",
                    str(fixtures.PROFILES_PATH),
                    "--data-dir",
                    str(root / "state"),
                    "--presidio-mode",
                    "disabled",
                    "evaluate",
                    "--no-record",
                    option,
                    str(path),
                ]
                if option == "--candidate-output-file":
                    args.extend(["--input", "A safe request."])
                try:
                    with (
                        patch.object(app, "_reject_path_links", side_effect=race),
                        patch.object(
                            app.PrivacyKey,
                            "_load_or_create",
                            return_value=fixtures.TEST_KEY,
                        ),
                        patch("sys.stdout", stdout),
                        patch("sys.stderr", stderr),
                    ):
                        code = app.main(args)
                    self.assertTrue(swapped)
                    self.assertNotIn(
                        SYNTHETIC_REDIRECTED_TEXT, stdout.getvalue() + stderr.getvalue()
                    )
                    self.assertNotEqual(code, app.EXIT_OK)
                finally:
                    if swapped:
                        remove_link(requested)

    def test_plain_unicode_files_and_direct_input_remain_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "input.txt"
            path.write_text("A safe résumé.", encoding="utf-8")
            self.assertEqual(
                app._read_cli_text(str(path), None, "input"), "A safe résumé."
            )
            self.assertEqual(app._read_cli_text(None, "direct", "input"), "direct")

    @unittest.skipUnless(os.name == "posix", "POSIX FIFO API")
    def test_fifo_input_refuses_before_blocking_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "input.txt"
            os.mkfifo(path, 0o600)
            with self.assertRaises(app.InputValidationError):
                app._read_cli_text(str(path), None, "input")


class AuditReadBoundaryTests(unittest.TestCase):
    def test_pinned_private_audit_descriptor_validates_before_any_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            audit = root / "audit"
            parent_fd = app._open_private_key(audit, create=True, directory=True)
            try:
                config = fixtures.base_config(root)
                store = app.AuditStore(
                    config, app.AwsClientProvider(config, live_authorized=False)
                )
                core = {"previous_hash": None, "event_type": "synthetic"}
                digest = app._sha256_bytes(app._canonical_json(core))
                data = app._canonical_json({**core, "record_hash": digest}) + b"\n"
                fd = app._open_private_key(
                    store.events_path, create=True, parent_fd=parent_fd
                )
                with os.fdopen(fd, "wb") as output:
                    output.write(data)
                self.assertEqual(store._last_event_hash(parent_fd), digest)
                os.link(store.events_path, root / "alias.ndjson")
                with self.assertRaises(app.StorageError):
                    store._last_event_hash(parent_fd)
            finally:
                os.close(parent_fd)

    @unittest.skipUnless(os.name == "posix", "POSIX parent rename API")
    def test_audit_recovery_parent_swap_cannot_change_selected_tail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            system = app.BedrockGuardrailSystem(
                fixtures.base_config(root), privacy_key=fixtures.TEST_KEY
            )
            result = system.process("A safe request.", {}, record=True)
            digest = result["audit"]["record_hash"]
            alternate = root / "alternate"
            alternate.mkdir(mode=0o700)
            (alternate / "events.ndjson").write_text("not-json-synthetic\n")
            original = app._open_private_key
            swapped = False

            def race(path, **kwargs):
                nonlocal swapped
                if (
                    Path(path) == system.audit.events_path
                    and kwargs.get("parent_fd") is not None
                    and not swapped
                ):
                    replace_directory_with_link(system.audit.audit_dir, alternate)
                    swapped = True
                return original(path, **kwargs)

            try:
                with patch.object(app, "_open_private_key", side_effect=race):
                    self.assertEqual(system.audit._last_event_hash(), digest)
                self.assertTrue(swapped)
            finally:
                if swapped:
                    remove_link(system.audit.audit_dir)

    @unittest.skipUnless(os.name == "posix", "POSIX FIFO API")
    def test_public_verify_and_evaluate_fifo_refuse_within_deadline(self):
        for command in (
            ["verify-audit", "--expected-count", "0"],
            ["evaluate", "--input", "A safe request."],
        ):
            with (
                self.subTest(command=command),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory).resolve()
                audit = root / "audit"
                audit.mkdir(mode=0o700)
                os.mkfifo(audit / "events.ndjson", 0o600)
                result = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "orchestrator.py"),
                        "--policy",
                        str(fixtures.POLICY_PATH),
                        "--profiles",
                        str(fixtures.PROFILES_PATH),
                        "--data-dir",
                        str(root),
                        "--presidio-mode",
                        "disabled",
                        *command,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertNotIn('"content_released": true', result.stdout)
                if command[0] == "verify-audit":
                    self.assertNotEqual(result.returncode, app.EXIT_OK)
                else:
                    self.assertIn("local_audit_failed", result.stdout)

    def test_valid_recovery_and_trusted_checkpoint_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            config = fixtures.base_config(Path(directory).resolve())
            system = app.BedrockGuardrailSystem(config, privacy_key=fixtures.TEST_KEY)
            result = system.process("A safe request.", {}, record=True)
            digest = result["audit"]["record_hash"]
            self.assertEqual(system.audit._last_event_hash(), digest)
            self.assertTrue(
                system.audit.verify(expected_count=1, expected_last_hash=digest)["ok"]
            )

    def test_hardlinked_events_refuse_before_recovery_or_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            system = app.BedrockGuardrailSystem(
                fixtures.base_config(root), privacy_key=fixtures.TEST_KEY
            )
            result = system.process("A safe request.", {}, record=True)
            os.link(system.audit.events_path, root / "alias.ndjson")
            with self.assertRaises(app.StorageError):
                system.audit._last_event_hash()
            self.assertFalse(
                system.audit.verify(
                    expected_count=1, expected_last_hash=result["audit"]["record_hash"]
                )["ok"]
            )


if __name__ == "__main__":
    unittest.main()
