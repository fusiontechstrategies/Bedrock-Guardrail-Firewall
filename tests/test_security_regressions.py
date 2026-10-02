from __future__ import annotations

import json

import orchestrator as app

from tests.test_orchestrator import FakeBedrockClient, GuardrailTestCase


class SecurityRegressionTests(GuardrailTestCase):
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
