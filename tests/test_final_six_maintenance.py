from __future__ import annotations

import json
import os
import socket
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import orchestrator as app
from scripts import prepare_release_evidence as release
from tests.private_state_fixture import PrivateTemporaryDirectory
from tests.test_orchestrator import (
    FakeBedrockClient,
    GuardrailTestCase,
    POLICY_PATH,
    PROFILES_PATH,
    base_config,
)
from tests import test_release_evidence as release_fixtures

VERSION = release_fixtures.VERSION


class FinalSixSourceMaintenanceTests(GuardrailTestCase):
    def test_supported_ascii_privacy_formats_with_unicode_delimiters(self):
        fixtures = {
            "AWS_ACCESS_KEY": "AKIA" + "A" * 16,
            "AWS_SECRET_ACCESS_KEY": "AWSSecretAccessKey=" + "A" * 40,
            "GITHUB_TOKEN": "ghp_" + "A" * 32,
            "SLACK_TOKEN": "xoxb-" + "A" * 24,
            "OPENAI_API_KEY": "sk-" + "A" * 32,
            "EMAIL_ADDRESS": "fixture@example.invalid",
            "IBAN_CODE": "GB82WEST12345698765432",
            "CUI_MARKING": "NOFORN",
        }
        system = self.make_system()
        for entity, value in fixtures.items():
            for edge in ("\u03a9", "\u0416", "\u754c", "\u00e9"):
                for text in (edge + value, value + edge, edge + value + edge):
                    with self.subTest(entity=entity, edge=edge, text=text):
                        result = system.privacy.evaluate(text, "input")
                        self.assertIn(entity, {d.category for d in result.detections})
                        self.assertNotIn(value, result.sanitized_text)

    def test_larger_ascii_identifiers_preserve_credential_boundaries(self):
        system = self.make_system()
        for entity, value in (
            ("AWS_ACCESS_KEY", "AKIA" + "A" * 16),
            ("GITHUB_TOKEN", "ghp_" + "A" * 32),
            ("SLACK_TOKEN", "xoxb-" + "A" * 24),
            ("OPENAI_API_KEY", "sk-" + "A" * 32),
            ("CUI_MARKING", "NOFORN"),
        ):
            with self.subTest(entity=entity):
                result = system.privacy.evaluate("prefix_" + value + "_suffix", "input")
                self.assertNotIn(entity, {d.category for d in result.detections})

    def test_secret_assignment_preserves_unicode_whitespace_syntax(self):
        system = self.make_system()
        for separator in (" ", "\t", "\u2028", "\u2029", "\u2003"):
            text = (
                "\u754cAWSSecretAccessKey"
                + separator
                + "="
                + separator
                + "A" * 40
                + "\u754c"
            )
            with self.subTest(separator=separator):
                result = system.privacy.evaluate(text, "input")
                self.assertIn(
                    "AWS_SECRET_ACCESS_KEY", {d.category for d in result.detections}
                )
                self.assertNotIn("A" * 40, result.sanitized_text)

    def test_default_privacy_blocks_mock_sdk_and_public_release(self):
        client = FakeBedrockClient()
        system = self.make_live_system(client)
        with patch.object(
            socket, "create_connection", side_effect=AssertionError("No network")
        ):
            for text in (
                "\u754c" + "AKIA" + "A" * 16 + "\u754c",
                "\u03a9" + "ghp_" + "A" * 32 + "\u03a9",
            ):
                result = system.process(
                    text, candidate_output="Ordinary short output.", record=False
                )
                self.assertFalse(result["content_released"])
                self.assertEqual(result["sanitized_input"], "")
        self.assertEqual(client.calls, [])

    def test_standard_benign_mock_sdk_positive(self):
        client = FakeBedrockClient()
        system = self.make_live_system(client)
        with patch.object(
            socket, "create_connection", side_effect=AssertionError("No network")
        ):
            result = system.process(
                "Ordinary short request.",
                candidate_output="Ordinary short output.",
                record=False,
            )
        self.assertTrue(result["content_released"])
        self.assertEqual([c["source"] for c in client.calls], ["INPUT", "OUTPUT"])

    def test_supported_privacy_format_in_output_and_retrieval(self):
        value = "\u754c" + "AKIA" + "A" * 16 + "\u754c"
        for candidate, context in (
            (value, {}),
            (
                "Ordinary output.",
                {"retrieval_contexts": [{"id": "fixture", "text": value}]},
            ),
        ):
            client = FakeBedrockClient()
            system = self.make_live_system(client)
            with patch.object(
                socket, "create_connection", side_effect=AssertionError("No network")
            ):
                result = system.process(
                    "Ordinary input.", context, candidate, record=False
                )
            self.assertFalse(result["content_released"])
            self.assertEqual(client.calls, [])

    def test_omitted_archive_source_is_refused_before_artifact_acquisition(self):
        with patch.object(release, "artifact_snapshot") as acquire:
            with self.assertRaises(release.ReleaseEvidenceError):
                release.validate_wheel(Path("ordinary.whl"), VERSION, [])
            with self.assertRaises(release.ReleaseEvidenceError):
                release.validate_sdist(Path("ordinary.tar.gz"), VERSION)
        acquire.assert_not_called()

    def test_exact_policy_booleans_are_required(self):
        policy = json.loads(POLICY_PATH.read_text())
        profiles = json.loads(PROFILES_PATH.read_text())
        name = next(iter(profiles["profiles"]))
        with PrivateTemporaryDirectory(prefix="six-policy-") as directory:
            root = Path(directory)
            policy_path, profile_path = root / "policy.json", root / "profiles.json"
            for field in (
                "citation_required",
                "aws_guardrail_required",
                "presidio_required",
            ):
                for value in (0, 1, "", "false", [], {}, None):
                    current_policy = json.loads(json.dumps(policy))
                    current_profiles = json.loads(json.dumps(profiles))
                    if field == "citation_required":
                        current_policy["grounding"][field] = value
                    else:
                        current_profiles["profiles"][name][field] = value
                    policy_path.write_text(json.dumps(current_policy))
                    profile_path.write_text(json.dumps(current_profiles))
                    with (
                        self.subTest(field=field, value=value),
                        self.assertRaisesRegex(
                            app.ConfigurationError, field + ".*JSON boolean"
                        ),
                    ):
                        app.load_policy_bundle(policy_path, profile_path)
                for value in (False, True):
                    current_policy = json.loads(json.dumps(policy))
                    current_profiles = json.loads(json.dumps(profiles))
                    if field == "citation_required":
                        current_policy["grounding"][field] = value
                    else:
                        current_profiles["profiles"][name][field] = value
                    policy_path.write_text(json.dumps(current_policy))
                    profile_path.write_text(json.dumps(current_profiles))
                    bundle = app.load_policy_bundle(policy_path, profile_path)
                    actual = (
                        bundle.grounding[field]
                        if field == "citation_required"
                        else getattr(bundle.profiles[name], field)
                    )
                    self.assertIs(actual, value)

    def test_archive_api_requires_explicit_reviewed_source(self):
        with PrivateTemporaryDirectory(prefix="six-archive-") as directory:
            root = Path(directory)
            helper = release_fixtures.ReleaseEvidenceTests()
            helper.make_source(root)
            helper.make_distributions(root / "dist")
            wheel = next((root / "dist").glob("*.whl"))
            sdist = next((root / "dist").glob("*.tar.gz"))
            dependencies = release.parse_optional_dependencies(root)
            with self.assertRaisesRegex(
                release.ReleaseEvidenceError, "Reviewed source"
            ):
                release.validate_wheel(wheel, VERSION, dependencies)
            with self.assertRaisesRegex(
                release.ReleaseEvidenceError, "Reviewed source"
            ):
                release.validate_sdist(sdist, VERSION)
            self.assertEqual(
                release.validate_wheel(wheel, VERSION, dependencies, root), dependencies
            )
            release.validate_sdist(sdist, VERSION, root)

    def test_post_transformation_current_permission_before_mock_output(self):
        for action in (
            app.GuardrailAction.REVIEW,
            app.GuardrailAction.ESCALATE,
            app.GuardrailAction.BLOCK,
        ):
            client = FakeBedrockClient(
                responses=[
                    {
                        "action": "GUARDRAIL_INTERVENED",
                        "assessments": [
                            {
                                "sensitiveInformationPolicy": {
                                    "piiEntities": [
                                        {"action": "ANONYMIZED", "detected": True}
                                    ]
                                }
                            }
                        ],
                        "outputs": [{"text": "Ordinary transformed input."}],
                    }
                ]
            )
            system = self.make_live_system(client)
            original = system.privacy.evaluate

            def transformed(text, field, original=original, action=action):
                value = original(text, field)
                if field == "aws_input_output":
                    value.detections.append(
                        app.Detection(
                            detector="synthetic_local_control",
                            category="synthetic_transform",
                            field=field,
                            action=action,
                            severity="high",
                            confidence=1.0,
                        )
                    )
                return value

            with (
                self.subTest(action=action),
                patch.object(system.privacy, "evaluate", side_effect=transformed),
                patch.object(
                    socket,
                    "create_connection",
                    side_effect=AssertionError("No network"),
                ),
            ):
                result = system.process(
                    "Ordinary input.", candidate_output="Ordinary output.", record=False
                )
                self.assertEqual([c["source"] for c in client.calls], ["INPUT"])
                self.assertIn(
                    "aws_output:skipped_prior_decision", result["diagnostics"]
                )
                self.assertFalse(result["content_released"])

    def test_audit_ordinary_concurrent_writers_and_verifier_are_coherent(self):
        system = self.make_system()
        failures = []
        barrier = threading.Barrier(3)

        def writer(worker):
            try:
                barrier.wait()
                for sequence in range(12):
                    system.audit.write(
                        {
                            "event_type": "synthetic",
                            "worker": worker,
                            "sequence": sequence,
                        }
                    )
            except Exception as error:
                failures.append(error)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for _ in range(16):
            result = system.audit.verify()
            self.assertTrue(result.get("integrity_ok"), result)
            self.assertEqual(result["error"], "trusted_checkpoint_required")
        for thread in threads:
            thread.join(timeout=15)
            self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        result = system.audit.verify()
        self.assertEqual(result["checked"], 24)
        verified = system.audit.verify(
            expected_count=24, expected_last_hash=result["last_hash"]
        )
        self.assertTrue(verified["ok"], verified)

    def test_canonical_empty_audit_checkpoint_across_supported_representations(self):
        for events_present, head_present in (
            (False, False),
            (True, False),
            (False, True),
            (True, True),
        ):
            system = self.make_system()
            audit = system.audit
            descriptor = app._open_private_key(
                audit.audit_dir, create=True, directory=True
            )
            os.close(descriptor)
            if events_present:
                descriptor = app._open_private_key(audit.events_path, create=True)
                os.close(descriptor)
            if head_present:
                app._atomic_json_write(
                    audit.chain_path, {"schema_version": 1, "last_hash": None}
                )
            with self.subTest(events=events_present, head=head_present):
                result = audit.verify(expected_count=0)
                self.assertTrue(result["ok"], result)
                self.assertIsNone(result["last_hash"])
                self.assertEqual(audit.verify()["error"], "trusted_checkpoint_required")
                for inconsistent in ("", "0" * 64, False, 1):
                    with self.assertRaises(app.InputValidationError):
                        audit.verify(expected_count=0, expected_last_hash=inconsistent)
                with self.assertRaises(app.InputValidationError):
                    audit.verify(expected_last_hash="0" * 64)

    def test_zero_checkpoint_cannot_match_a_nonempty_valid_stream(self):
        system = self.make_system()
        system.audit.write({"event_type": "synthetic"})
        result = system.audit.verify(expected_count=0)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "trusted_checkpoint_mismatch")

    def test_behavior_byte_eviction_remains_readable_with_high_count_capacity(self):
        with (
            PrivateTemporaryDirectory(prefix="six-behavior-") as directory,
            patch.object(app, "MAX_BEHAVIOR_STATE_BYTES", 1100),
        ):
            store = app.BehaviorStore(
                base_config(Path(directory), behavior_max_subjects=1_000_000)
            )
            for index in range(16):
                identifier = "\u754c" * 80 + str(index)
                store.record(
                    identifier, app.GuardrailAction.ALLOW, app.RiskLevel.LOW, []
                )
                self.assertLessEqual(
                    store.path.stat().st_size, app.MAX_BEHAVIOR_STATE_BYTES
                )
                loaded = store._load()
                self.assertIn(identifier, loaded["subjects"])
            self.assertLess(len(loaded["subjects"]), 16)
            self.assertEqual(store.score(identifier), 0.0)

    def test_behavior_actual_shared_budget_guard_preserves_prior_file(self):
        with PrivateTemporaryDirectory(prefix="six-write-") as directory:
            path = Path(directory) / "state.json"
            app._atomic_json_write(
                path, {"subjects": {}}, compact=True, maximum_bytes=64
            )
            before = path.read_bytes()
            with self.assertRaises(app.StorageError):
                app._atomic_json_write(
                    path,
                    {"subjects": {"long": "x" * 100}},
                    compact=True,
                    maximum_bytes=64,
                )
            self.assertEqual(path.read_bytes(), before)

    def test_compact_encoded_boundary_and_existing_pretty_json_compatibility(self):
        with PrivateTemporaryDirectory(prefix="six-encoded-") as directory:
            root = Path(directory)
            value = {"schema_version": 1, "subjects": {}, "note": "\u754c\U0001f600"}
            limit = len(app._compact_state_json(value)) + 1
            app._atomic_json_write(
                root / "exact.json", value, compact=True, maximum_bytes=limit
            )
            self.assertEqual((root / "exact.json").stat().st_size, limit)
            with self.assertRaises(app.StorageError):
                app._atomic_json_write(
                    root / "small.json", value, compact=True, maximum_bytes=limit - 1
                )
            self.assertFalse((root / "small.json").exists())
            store = app.BehaviorStore(base_config(root))
            app._atomic_json_write(store.path, value)
            store.record(
                "ordinary-subject", app.GuardrailAction.ALLOW, app.RiskLevel.LOW, []
            )
            self.assertEqual(store._load()["note"], value["note"])
            self.assertEqual(store._load()["subjects"]["ordinary-subject"]["events"], 1)


if __name__ == "__main__":
    unittest.main()
