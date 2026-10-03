from __future__ import annotations

import json
import socket
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import orchestrator as app
from tests.private_state_fixture import PrivateTemporaryDirectory
from tests.test_orchestrator import (
    POLICY_PATH,
    PROFILES_PATH,
    FakeBedrockClient,
    GuardrailTestCase,
    base_config,
)


def ordinary_response(**updates):
    return {"action": "NONE", "assessments": [], "outputs": [], "usage": {}, **updates}


def transformed_response(*values):
    return ordinary_response(
        action="GUARDRAIL_INTERVENED",
        assessments=[
            {"sensitiveInformationPolicy": {"piiEntities": [{"action": "ANONYMIZED"}]}}
        ],
        outputs=[{"text": value} for value in values],
    )


class RequiredIntegrationAdmissionTests(GuardrailTestCase):
    def test_required_failure_actions_are_semantically_validated(self):
        policy = json.loads(POLICY_PATH.read_text())
        profiles = json.loads(PROFILES_PATH.read_text())
        with PrivateTemporaryDirectory(prefix="three-policy-") as directory:
            policy_path = Path(directory) / "policy.json"
            profile_path = Path(directory) / "profiles.json"
            policy_path.write_text(json.dumps(policy))
            for flag, action_field in (
                ("presidio_required", "presidio_failure_action"),
                ("aws_guardrail_required", "external_failure_action"),
            ):
                for action in ("allow", "sanitize"):
                    candidate = json.loads(json.dumps(profiles))
                    profile = candidate["profiles"]["balanced"]
                    profile[flag] = True
                    profile[action_field] = action
                    profile_path.write_text(json.dumps(candidate))
                    with (
                        self.subTest(flag=flag, action=action),
                        self.assertRaisesRegex(
                            app.ConfigurationError, action_field + ".*queue_for_review"
                        ),
                    ):
                        app.load_policy_bundle(policy_path, profile_path)
                    profile[flag] = False
                    profile_path.write_text(json.dumps(candidate))
                    self.assertEqual(
                        getattr(
                            app.load_policy_bundle(policy_path, profile_path).profiles[
                                "balanced"
                            ],
                            action_field,
                        ),
                        app.GuardrailAction(action),
                    )

    def test_runtime_required_presidio_admission_precedes_state_or_provider(self):
        bundle = app.load_policy_bundle(POLICY_PATH, PROFILES_PATH)
        for action in (app.GuardrailAction.ALLOW, app.GuardrailAction.SANITIZE):
            profile = replace(
                bundle.profiles["balanced"], presidio_failure_action=action
            )
            candidate = replace(bundle, profiles={"balanced": profile})
            with (
                self.subTest(action=action),
                patch.object(app, "_auxiliary_namespace") as state,
                patch.object(app, "AwsClientProvider") as provider,
                self.assertRaisesRegex(
                    app.ConfigurationError, "presidio_failure_action"
                ),
            ):
                app.BedrockGuardrailSystem(
                    base_config(Path("unused"), presidio_mode="required"),
                    policy_bundle=candidate,
                )
            state.assert_not_called()
            provider.assert_not_called()

    def test_checked_in_profiles_and_safe_required_actions_remain_valid(self):
        bundle = app.load_policy_bundle(POLICY_PATH, PROFILES_PATH)
        for profile in bundle.profiles.values():
            app._validate_required_failure_actions(profile)
        for action in (
            app.GuardrailAction.REVIEW,
            app.GuardrailAction.ESCALATE,
            app.GuardrailAction.BLOCK,
        ):
            profile = replace(
                bundle.profiles["balanced"],
                presidio_required=True,
                aws_guardrail_required=True,
                presidio_failure_action=action,
                external_failure_action=action,
            )
            app._validate_required_failure_actions(profile)
            self.assertEqual(app._required_failure_action(action, True), action)

    def test_direct_required_presidio_failures_have_minimum_review(self):
        system = self.make_system()
        for action in (app.GuardrailAction.ALLOW, app.GuardrailAction.SANITIZE):
            system.privacy.profile = replace(
                system.profile, presidio_required=True, presidio_failure_action=action
            )
            for mode, error in (("disabled", None), ("required", "FixtureUnavailable")):
                system.privacy.config = replace(system.config, presidio_mode=mode)
                system.privacy.analyzer_error = error
                with patch.object(
                    system.privacy, "_presidio_findings", return_value=[]
                ):
                    result = system.privacy.evaluate("Ordinary short text.", "input")
                failures = [d for d in result.detections if d.detector == "system"]
                self.assertTrue(failures)
                self.assertTrue(
                    all(d.action == app.GuardrailAction.REVIEW for d in failures)
                )

    def test_direct_required_bedrock_failures_have_minimum_review(self):
        system = self.make_system()
        for action in (app.GuardrailAction.ALLOW, app.GuardrailAction.SANITIZE):
            profile = replace(
                system.profile,
                aws_guardrail_required=True,
                external_failure_action=action,
            )
            for mode, identifier, client in (
                ("disabled", "fixture", FakeBedrockClient()),
                ("preview", "fixture", FakeBedrockClient()),
                ("live", "", FakeBedrockClient()),
                ("live", "fixture", FakeBedrockClient(failure=TimeoutError("fixture"))),
                ("live", "fixture", FakeBedrockClient(responses=[{}])),
            ):
                adapter = app.BedrockGuardrailAdapter(
                    replace(
                        system.config,
                        aws_mode=mode,
                        aws_guardrail_id=identifier,
                        aws_guardrail_version="1",
                    ),
                    profile,
                    system.provider,
                    injected_client=client,
                )
                with patch.object(
                    socket,
                    "create_connection",
                    side_effect=AssertionError("No network"),
                ):
                    result = adapter.evaluate(
                        source="INPUT", text="Ordinary text.", field_name="input"
                    )
                self.assertEqual(result.action, app.GuardrailAction.REVIEW)
                self.assertIsNone(result.sanitized_text)

    def test_optional_failure_actions_are_preserved(self):
        system = self.make_system()
        for action in (app.GuardrailAction.ALLOW, app.GuardrailAction.SANITIZE):
            profile = replace(system.profile, external_failure_action=action)
            adapter = app.BedrockGuardrailAdapter(
                replace(
                    system.config,
                    aws_mode="live",
                    aws_guardrail_id="fixture",
                    aws_guardrail_version="1",
                ),
                profile,
                system.provider,
                injected_client=FakeBedrockClient(failure=TimeoutError("fixture")),
            )
            self.assertEqual(
                adapter.evaluate(
                    source="INPUT", text="Ordinary text.", field_name="input"
                ).action,
                action,
            )


class OpaqueFormatCompatibilityTests(GuardrailTestCase):
    def test_unicode_separator_and_value_whitespace_are_supported(self):
        system = self.make_system()
        token = "fixture_token_0001"
        for separator in (
            " ",
            "\t",
            "\n",
            "\u2028",
            "\u2029",
            "\u1680",
            "\u00a0",
            "\u2003",
        ):
            for label in (
                "access_token" + separator + "=" + separator,
                "REFRESH_TOKEN" + separator + ":" + separator,
                "Authorization" + separator + ":" + separator + "Bearer" + separator,
                "bEaReR" + separator,
            ):
                for field in ("input", "output", "retrieval_context"):
                    with self.subTest(separator=separator, label=label, field=field):
                        result = system.privacy.evaluate(
                            label + token + separator + "ordinary", field
                        )
                        self.assertIn(
                            "OPAQUE_TOKEN", {d.category for d in result.detections}
                        )
                        self.assertNotIn(token, result.sanitized_text)
                        self.assertIn("ordinary", result.sanitized_text)

    def test_ascii_labels_and_documented_benign_exclusions_remain_exact(self):
        system = self.make_system()
        for text in (
            "Bearer bonds",
            "access_token=placeholder",
            "refresh_token=redacted",
        ):
            result = system.privacy.evaluate(text, "input")
            self.assertNotIn("OPAQUE_TOKEN", {d.category for d in result.detections})


class BoundedResponseContractTests(unittest.TestCase):
    def refuse_before_projection(self, response, **small_limits):
        limits = replace(app.BEDROCK_RESPONSE_LIMITS, **small_limits)
        with (
            patch.object(app, "BEDROCK_RESPONSE_LIMITS", limits),
            patch.object(
                app.BedrockGuardrailAdapter, "_assessment_detections"
            ) as project,
            self.assertRaises(app.ExternalServiceError),
        ):
            app.BedrockGuardrailAdapter._parse_response(response, "output")
        project.assert_not_called()

    def test_small_cardinality_limits_apply_before_projection(self):
        self.refuse_before_projection(
            ordinary_response(assessments=[{}, {}]), assessments=1
        )
        self.refuse_before_projection(
            ordinary_response(outputs=[{"text": "one"}, {"text": "two"}]), outputs=1
        )
        self.refuse_before_projection(
            ordinary_response(usage={"one": 1, "two": 2}), usage_keys=1
        )
        self.refuse_before_projection(
            ordinary_response(ResponseMetadata={"one": 1, "two": 2}),
            mapping_keys=4,
            total_keys=5,
        )
        self.refuse_before_projection(
            ordinary_response(ResponseMetadata={"one": 1, "two": 2}), mapping_keys=1
        )
        self.refuse_before_projection(
            ordinary_response(extra=[1, 2]), collection_items=1
        )

    def test_policy_and_aggregate_finding_limits_apply_before_projection(self):
        findings = [{"action": "BLOCKED"}, {"action": "BLOCKED"}]
        response = ordinary_response(
            assessments=[{"topicPolicy": {"topics": findings}}]
        )
        self.refuse_before_projection(response, policy_findings=1)
        self.refuse_before_projection(response, total_findings=1)
        second = ordinary_response(
            assessments=[
                {"topicPolicy": {"topics": findings[:1]}},
                {"contentPolicy": {"filters": findings[:1]}},
            ]
        )
        self.refuse_before_projection(second, total_findings=1)

    def test_small_structure_string_and_encoded_budgets(self):
        response = ordinary_response(ResponseMetadata={"nested": {"value": "plain"}})
        self.refuse_before_projection(response, depth=2)
        self.refuse_before_projection(response, nodes=4)
        self.refuse_before_projection(response, string_chars=4)
        self.refuse_before_projection(
            ordinary_response(extra="\u754c\u754c"), string_bytes=5
        )
        self.refuse_before_projection(ordinary_response(), key_chars=3)
        self.refuse_before_projection(ordinary_response(), encoded_bytes=16)

    def test_compact_encoded_budget_matches_ordinary_json_bytes(self):
        response = ordinary_response(
            ResponseMetadata={"note": 'quote" slash\\ line\n \u754c \U0001f600'}
        )
        size = len(
            json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
        )
        with patch.object(
            app,
            "BEDROCK_RESPONSE_LIMITS",
            replace(app.BEDROCK_RESPONSE_LIMITS, encoded_bytes=size),
        ):
            result = app.BedrockGuardrailAdapter._parse_response(response, "output")
        self.assertEqual(result.action, app.GuardrailAction.ALLOW)
        self.refuse_before_projection(response, encoded_bytes=size - 1)

    def test_transformed_text_character_and_utf8_join_budgets(self):
        for values, maximum in (
            (("one", "two"), 6),
            (("\u754c", "\u754c"), 6),
            (("a\x00b",), 8),
        ):
            with (
                self.subTest(values=values),
                self.assertRaises(app.ExternalServiceError),
            ):
                app.BedrockGuardrailAdapter._parse_response(
                    transformed_response(*values), "output", maximum
                )
        result = app.BedrockGuardrailAdapter._parse_response(
            transformed_response("\u754c", "\u754c"), "output", 7
        )
        self.assertEqual(result.sanitized_text, "\u754c\n\u754c")

    def test_scalar_and_unicode_contract_refusals_are_small(self):
        for value in (float("inf"), float("nan"), 1 << 65, "\ud800"):
            self.refuse_before_projection(ordinary_response(extra=value))
        self.refuse_before_projection(ordinary_response(extra={1: "plain"}))

    def test_standard_metadata_usage_and_bounded_findings_remain_supported(self):
        result = app.BedrockGuardrailAdapter._parse_response(
            ordinary_response(
                assessments=[
                    {
                        "topicPolicy": {"topics": [{"action": "BLOCKED"}] * 3},
                        "invocationMetrics": {"guardrailProcessingLatency": 12},
                    }
                ],
                usage={"topicPolicyUnits": 1},
                ResponseMetadata={
                    "HTTPStatusCode": 200,
                    "RetryAttempts": 0,
                    "HTTPHeaders": {"content-type": "application/json"},
                },
            ),
            "input",
        )
        self.assertEqual(result.action, app.GuardrailAction.BLOCK)
        self.assertEqual(result.latency_ms, 12)
        self.assertEqual(result.usage, {"topicPolicyUnits": 1})
        self.assertEqual(len(result.detections), 3)
        self.assertTrue(all(item.count == 1 for item in result.detections))


class ResponseProjectionIntegrationTests(GuardrailTestCase):
    def test_small_response_budget_failure_uses_required_failure_minimum(self):
        client = FakeBedrockClient(
            responses=[ordinary_response(outputs=[{"text": "one"}, {"text": "two"}])]
        )
        system = self.make_live_system(client)
        system.aws_guardrail.profile = replace(
            system.profile,
            aws_guardrail_required=True,
            external_failure_action=app.GuardrailAction.ALLOW,
        )
        with patch.object(
            app,
            "BEDROCK_RESPONSE_LIMITS",
            replace(app.BEDROCK_RESPONSE_LIMITS, outputs=1),
        ):
            result = system.aws_guardrail.evaluate(
                source="INPUT", text="Ordinary text.", field_name="input"
            )
        self.assertEqual(result.action, app.GuardrailAction.REVIEW)
        self.assertEqual(result.status, "failed")
        self.assertEqual(
            result.detections[0].details["error_type"], "ExternalServiceError"
        )

    def test_service_findings_preserve_original_projection_order_and_metrics(self):
        system = self.make_system()
        result = app.BedrockGuardrailAdapter._parse_response(
            ordinary_response(
                assessments=[
                    {
                        "topicPolicy": {
                            "topics": [{"action": "NONE", "detected": True}] * 2
                        }
                    }
                ]
            ),
            "input",
        )
        single = result.detections[0]
        self.assertEqual(result.detections, [single, single])
        self.assertEqual(
            system.risk.score(result.detections, 0),
            system.risk.score([single, single], 0),
        )
        system.metrics.record(
            app.GuardrailAction.REVIEW, app.RiskLevel.MEDIUM, result.detections
        )
        metrics = system.metrics._load()
        self.assertEqual(metrics["detectors"]["aws_bedrock_guardrail"], 2)

    def test_bounded_findings_preserve_custom_threshold_and_order_semantics(self):
        system = self.make_system()
        response = ordinary_response(
            assessments=[
                {
                    "topicPolicy": {
                        "topics": [{"action": "NONE", "detected": True}] * 2
                    },
                    "contentPolicy": {
                        "filters": [{"action": "NONE", "detected": True}]
                    },
                    "wordPolicy": {
                        "customWords": [{"action": "NONE", "detected": True}]
                    },
                },
                {
                    "topicPolicy": {
                        "topics": [{"action": "NONE", "detected": True}] * 2
                    },
                    "contentPolicy": {
                        "filters": [{"action": "NONE", "detected": True}]
                    },
                },
            ]
        )
        parsed = app.BedrockGuardrailAdapter._parse_response(response, "input")
        expected_categories = [
            "topic_policy",
            "topic_policy",
            "content_policy",
            "word_policy",
            "topic_policy",
            "topic_policy",
            "content_policy",
        ]
        expected = [
            app.Detection(
                detector="aws_bedrock_guardrail",
                category=category,
                field="input",
                action=app.GuardrailAction.REVIEW,
                severity="high",
                confidence=1.0,
            )
            for category in expected_categories
        ]
        self.assertEqual(parsed.detections, expected)
        for weight in (0.07, 0.13, 0.21):
            bundle = replace(
                system.bundle, risk_weights={"aws_bedrock_guardrail": weight}
            )
            for medium in (0.45, 0.6825, 0.7):
                profile = replace(
                    system.profile,
                    risk_thresholds={"low": 0.2, "medium": medium, "high": 0.9},
                )
                engine = app.RiskEngine(bundle, profile)
                with self.subTest(weight=weight, medium=medium):
                    self.assertEqual(
                        engine.score(parsed.detections, 0), engine.score(expected, 0)
                    )
