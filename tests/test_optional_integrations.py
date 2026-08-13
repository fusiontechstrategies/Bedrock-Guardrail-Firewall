# ruff: noqa: E402, I001
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import orchestrator as app


@unittest.skipUnless(app.BOTO3_AVAILABLE, "Optional boto3 integration is not installed")
class Boto3ContractTests(unittest.TestCase):
    def test_apply_guardrail_sdk_contract(self):
        import botocore.session

        service = botocore.session.get_session().get_service_model("bedrock-runtime")
        operation = service.operation_model("ApplyGuardrail")
        members = operation.input_shape.members
        self.assertTrue(
            {
                "guardrailIdentifier",
                "guardrailVersion",
                "source",
                "content",
                "outputScope",
            }.issubset(members)
        )
        self.assertEqual(set(members["source"].enum), {"INPUT", "OUTPUT"})
        text_shape = members["content"].member.members["text"]
        self.assertEqual(
            set(text_shape.members["qualifiers"].member.enum),
            {"grounding_source", "query", "guard_content"},
        )


@unittest.skipUnless(
    app.PRESIDIO_AVAILABLE, "Optional Presidio integration is not installed"
)
class PresidioIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="guardrail-presidio-")
        config = app.RuntimeConfig(
            policy_path=PROJECT_ROOT / "guardrail_policy.json",
            profiles_path=PROJECT_ROOT / "guardrail_policy_profiles.json",
            data_dir=Path(cls.temporary.name),
            presidio_mode="required",
            aws_mode="disabled",
        )
        cls.system = app.BedrockGuardrailSystem(
            config, privacy_key=b"optional-integration-test-key-32b"
        )

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_presidio_engine_initializes(self):
        report = self.system.doctor()
        check = next(
            item for item in report["checks"] if item["name"] == "presidio_engine"
        )
        self.assertEqual(check["status"], "pass")

    def test_presidio_detects_and_redacts_ip_address(self):
        result = self.system.privacy.evaluate(
            "Connect from documentation address 192.0.2.10.", "input"
        )
        finding = next(
            item for item in result.findings if item.entity_type == "IP_ADDRESS"
        )
        self.assertEqual(finding.recognizer, "presidio")
        self.assertNotIn("192.0.2.10", result.sanitized_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
