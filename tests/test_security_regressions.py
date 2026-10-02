from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import orchestrator as app

from tests.test_orchestrator import FakeBedrockClient, GuardrailTestCase


class SecurityRegressionTests(GuardrailTestCase):
    def test_kms_signature_is_verified_and_forged_tail_blocks_append(self):
        import hashlib
        import hmac

        class FakeSigner:
            def sign(self, **kwargs):
                return {
                    "Signature": hmac.digest(
                        b"separately-held-fixture", kwargs["Message"], "sha256"
                    )
                }

            def verify(self, **kwargs):
                expected = hmac.digest(
                    b"separately-held-fixture", kwargs["Message"], "sha256"
                )
                return {
                    "SignatureValid": hmac.compare_digest(expected, kwargs["Signature"])
                }

        system = self.make_live_system(
            FakeBedrockClient(),
            audit_signing_key_id="fixture",
            audit_signature_required=True,
        )
        system.provider._clients["kms"] = FakeSigner()
        result = system.process("Safe request.")
        checkpoint = result["audit"]["record_hash"]
        self.assertTrue(
            system.audit.verify(expected_last_hash=checkpoint, expected_count=1)["ok"]
        )
        record = json.loads(system.audit.events_path.read_text().strip())
        record["risk_score"] = 0.99
        core = {
            key: value
            for key, value in record.items()
            if key not in {"record_hash", "kms_signature", "kms_signing_algorithm"}
        }
        record["record_hash"] = hashlib.sha256(app._canonical_json(core)).hexdigest()
        system.audit.events_path.write_text(json.dumps(record) + "\n")
        system.audit.chain_path.write_text(
            json.dumps({"last_hash": record["record_hash"]})
        )
        self.assertEqual(
            system.audit.verify(expected_last_hash=checkpoint, expected_count=1)[
                "error"
            ],
            "audit_signature_invalid",
        )
        self.assertEqual(system.process("Another safe request.")["action"], "block")

    def test_required_remote_failure_is_recorded_as_final_block(self):
        from tests.test_orchestrator import RecordingClient

        system = self.make_live_system(
            FakeBedrockClient(), audit_bucket="fixture", remote_audit_required=True
        )
        system.provider._clients["s3"] = RecordingClient(
            failure=TimeoutError("fixture")
        )
        result = system.process("Safe request.")
        record = json.loads(system.audit.events_path.read_text().strip())
        self.assertEqual(record["enforced_action"], result["action"])
        self.assertEqual(record["recommended_action"], "block")
        self.assertIn("required_remote_audit_failed", record["diagnostics"])

    def test_structured_credentials_never_reach_cloud_or_response(self):
        for value in (
            '"SecretAccessKey": "' + "a" * 40 + '"',
            "AWSSecretAccessKey=" + "b" * 40,
            "github_pat_" + "c" * 82,
        ):
            for field in ("input", "output", "retrieval"):
                with self.subTest(field=field, value=value):
                    client = FakeBedrockClient()
                    system = self.make_live_system(client)
                    context = (
                        {"retrieval_contexts": [{"id": "fixture", "text": value}]}
                        if field == "retrieval"
                        else {}
                    )
                    result = system.process(
                        value if field == "input" else "Safe request.",
                        context,
                        value if field == "output" else "Safe response.",
                        record=False,
                    )
                    self.assertFalse(result["content_released"])
                    self.assertNotIn(value, json.dumps(client.calls))
                    self.assertNotIn(value, json.dumps(result))

    def test_unknown_and_malformed_cloud_responses_fail_closed(self):
        for response in (
            {},
            {"action": "ALLOW"},
            {"action": "NONE", "assessments": {}},
            {"action": "NONE", "assessments": [], "outputs": [1]},
        ):
            with self.subTest(response=response):
                system = self.make_live_system(FakeBedrockClient([response]))
                result = system.process("Safe request.", record=False)
                self.assertFalse(result["content_released"])

    def test_compound_repetition_is_rejected_without_evaluation(self):
        for pattern in (
            r"(?:a|aa)+$",
            r"(a|ab){2,100}$",
            r"(?:ab)+$",
            r"(?:a+){1,100}$",
        ):
            with (
                self.subTest(pattern=pattern),
                self.assertRaises(app.ConfigurationError),
            ):
                app._validate_safe_pattern(pattern, "fixture")
        app._validate_safe_pattern(r"a+[bc]{1,20}", "fixture")

    def test_monitor_reviews_and_critical_blocks_reach_defined_queues(self):
        monitor = self.make_system(enforcement_mode="monitor")
        result = monitor.process(
            "Synthetic CUI // controlled unclassified information", {}
        )
        self.assertIsNotNone(result["review"])
        critical = self.make_system()
        result = critical.process("Synthetic SSN 123-45-6789.", {})
        self.assertEqual(result["recommended_action"], "block")
        self.assertIsNotNone(result["review"])

    def test_untrusted_recomputed_audit_and_truncation_are_rejected(self):
        system = self.make_system()
        system.process("First safe request.")
        system.process("Second safe request.")
        trusted_hash = system.audit._last_event_hash()
        self.assertFalse(system.audit.verify()["ok"])
        lines = system.audit.events_path.read_text().splitlines()
        system.audit.events_path.write_text(lines[0] + "\n")
        first_hash = json.loads(lines[0])["record_hash"]
        system.audit.chain_path.write_text(json.dumps({"last_hash": first_hash}))
        result = system.audit.verify(expected_last_hash=trusted_hash, expected_count=2)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "trusted_checkpoint_mismatch")

    def test_evidence_quota_bounds_repeated_requests_and_preserves_existing_data(self):
        system = self.make_system()
        with patch.object(app, "MAX_EVIDENCE_FILES", 5):
            first = system.process("Synthetic SSN 123-45-6789.")
            previous = system.audit.events_path.read_bytes()
            for _ in range(3):
                result = system.process("Synthetic SSN 123-45-6789.")
            self.assertFalse(result["content_released"])
            self.assertTrue(first["incident_created"])
            self.assertTrue(system.audit.events_path.read_bytes().startswith(previous))
            self.assertLessEqual(
                sum(
                    1
                    for path in system.config.data_dir.rglob("*")
                    if path.is_file()
                    and path.parent.name in {"audit", "reviews", "incidents"}
                ),
                5,
            )

    def test_review_failure_is_in_final_audit(self):
        system = self.make_system()
        with patch.object(
            system.reviews, "create", side_effect=app.StorageError("fixture")
        ):
            result = system.process(
                "Synthetic CUI // controlled unclassified information", {}
            )
        record = json.loads(system.audit.events_path.read_text().splitlines()[-1])
        self.assertEqual(record["enforced_action"], result["action"])
        self.assertIn("review_storage_failed", record["diagnostics"])

    def test_privacy_key_rejects_hard_links(self):
        import os

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app.PrivacyKey(root)
            os.link(root / "privacy.key", root / "alias")
            with self.assertRaises(app.ConfigurationError):
                app.PrivacyKey(root)

    def test_canonicalized_private_text_never_reaches_cloud_or_response(self):
        for secret in ("ｔｅｓｔ＠ｅｘａｍｐｌｅ．ｃｏｍ", "test@exam\u200bple.com"):
            for route in ("input", "output", "retrieval"):
                with self.subTest(secret=secret, route=route):
                    client = FakeBedrockClient()
                    system = self.make_live_system(client)
                    context = {}
                    user_input, output = "Write a short summary.", "A safe summary."
                    if route == "input":
                        user_input = secret
                    elif route == "output":
                        output = secret
                    else:
                        context["retrieval_contexts"] = [{"id": "doc", "text": secret}]
                    result = system.process(user_input, context, output, record=False)
                    self.assertNotIn("test@example.com", json.dumps(client.calls))
                    self.assertNotIn("test@example.com", json.dumps(result))

    def test_action_only_intervention_blocks_input_and_output(self):
        for route in ("input", "output"):
            with self.subTest(route=route):
                responses = [
                    {"action": "GUARDRAIL_INTERVENED", "assessments": [], "outputs": []}
                ]
                if route == "output":
                    responses.insert(
                        0, {"action": "NONE", "assessments": [], "outputs": []}
                    )
                client = FakeBedrockClient(responses)
                result = self.make_live_system(client).process(
                    "Write a short summary.", {}, "A safe summary.", record=False
                )
                self.assertEqual(result["recommended_action"], "block")
                self.assertFalse(result["content_released"])
                self.assertFalse(any(result["capabilities"].values()))

    def test_unknown_capability_is_contained(self):
        result = self.make_system().process(
            "A safe request.",
            {"requested_capability": "unknown", "role": "user"},
            record=False,
        )
        self.assertFalse(result["content_released"])
        self.assertFalse(any(result["capabilities"].values()))

    def test_retrieval_permission_respects_trusted_policy(self):
        system = self.make_system()
        system.bundle.capability_roles["retrieval"] = ["admin"]
        permissions = system._capabilities({"role": "user"}, app.GuardrailAction.ALLOW)
        self.assertFalse(permissions["retrieval"])

    def test_repeated_request_ids_preserve_each_event(self):
        system = self.make_system()
        for tenant in ("one", "one", "two"):
            payload = {"tenant_id": tenant, "request_id_hash": "reused"}
            system.reviews.create(payload, "l1")
            system.incidents.create(payload)
        for directory in ("reviews", "incidents"):
            self.assertEqual(
                len(list((system.config.data_dir / directory).glob("*.json"))), 3
            )

    def test_evidence_collision_does_not_replace_existing_record(self):
        system = self.make_system()
        from unittest.mock import patch

        with patch.object(app.uuid, "uuid4", return_value=app.uuid.UUID(int=1)):
            for store, args in ((system.reviews, ("l1",)), (system.incidents, ())):
                path = store.create({"request_id_hash": "first"}, *args)
                with self.assertRaises(app.StorageError):
                    store.create({"request_id_hash": "second"}, *args)
                if isinstance(path, dict):
                    path = path["local_location"]
                self.assertIn("first", app.Path(path).read_text())
