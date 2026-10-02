from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
import tempfile
from dataclasses import asdict
from pathlib import Path

import orchestrator as app
from tests.test_orchestrator import (
    FakeBedrockClient,
    GuardrailTestCase,
    POLICY_PATH,
    PROFILES_PATH,
)


def encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def signed_token(header: str) -> str:
    body = encode(header.encode()) + "." + encode(b'{"sub":"synthetic-user"}')
    key = os.urandom(32)
    signature = hmac.new(key, body.encode(), hashlib.sha256).digest()
    token = body + "." + encode(signature)
    # Confirm whitespace is in the signed bytes, not a post-signing mutation.
    assert hmac.compare_digest(
        hmac.new(key, token.rsplit(".", 1)[0].encode(), hashlib.sha256).digest(),
        signature,
    )
    return token


class LatestPrivacyScanTests(GuardrailTestCase):
    def test_signed_jwt_serializations_are_contained_on_every_content_route(self):
        headers = (
            '{"alg":"HS256","typ":"JWT"}',
            ' {"alg":"HS256","typ":"JWT"}',
            '\n{"alg":"HS256","typ":"JWT"}',
            '{ "alg" : "HS256", "typ" : "JWT" }',
            '\r\n{\t"alg":"HS256"\n}',
            '{"typ":"JWT","alg":"HS256"}',
        )
        for header in headers:
            token = signed_token(header)
            for route in ("input", "output", "retrieval"):
                with self.subTest(header=header, route=route):
                    client = FakeBedrockClient()
                    system = self.make_live_system(client)
                    user_input, output, context = "Write a short summary.", "Safe.", {}
                    if route == "input":
                        user_input = "Bearer " + token
                    elif route == "output":
                        output = "Bearer " + token
                    else:
                        context["retrieval_contexts"] = [{"id": "doc", "text": token}]
                    result = system.process(user_input, context, output, record=False)
                    self.assertFalse(result["content_released"])
                    self.assertNotIn(token, json.dumps(result))
                    self.assertNotIn(token, json.dumps(client.calls))
                    self.assertTrue(
                        any(
                            x.entity_type == "JWT"
                            for x in system.privacy._regex_findings(token)
                        )
                    )

    def test_dotted_text_invalid_encoding_and_nonobject_headers_are_not_jwts(self):
        candidates = (
            "documentation.example.invalid",
            "1.2.3",
            "AAAA.AAAA.AAAA",
            encode(b'"not-an-object"') + ".e30.AAAA",
            encode(b'{"typ":"JWT"}') + ".e30.AAAA",
            encode(b'{"alg":42}') + ".e30.AAAA",
            encode(b'{"alg":"HS256"}') + ".a.AAAA",
            encode(b'{"alg":"HS256"}') + ".e30.a",
        )
        system = self.make_system()
        for value in candidates:
            with self.subTest(value=value):
                self.assertFalse(
                    any(
                        x.entity_type == "JWT"
                        for x in system.privacy._regex_findings(value)
                    )
                )

    def test_oversized_compact_candidates_fail_closed_before_decoding(self):
        system = self.make_system()
        for index, maximum in enumerate(app.MAX_JWT_SEGMENT_CHARS):
            segments = [encode(b'{"alg":"HS256"}'), "e30", "AAAA"]
            segments[index] = "A" * (maximum + 1)
            with (
                self.subTest(segment=index),
                self.assertRaises(app.InputValidationError),
            ):
                system.privacy._regex_findings(".".join(segments))

    def test_unsecured_compact_jwt_is_still_recognized_as_sensitive_content(self):
        token = encode(b'{ "alg": "none" }') + "." + encode(b'{"sub":"fixture"}') + "."
        system = self.make_system()
        self.assertTrue(
            any(x.entity_type == "JWT" for x in system.privacy._regex_findings(token))
        )


class LatestPolicyScanTests(GuardrailTestCase):
    def load_documents(self, policy, profiles):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "policy.json", root / "profiles.json"
            first.write_text(json.dumps(policy), encoding="utf-8")
            second.write_text(json.dumps(profiles), encoding="utf-8")
            return app.load_policy_bundle(first, second)

    def documents(self):
        return (
            json.loads(POLICY_PATH.read_text()),
            json.loads(PROFILES_PATH.read_text()),
        )

    def test_normalized_collisions_are_rejected_in_both_raw_orders(self):
        for map_name in (
            "denied_topics",
            "entity_actions",
            "capability_roles",
            "risk_weights",
            "profiles",
        ):
            for reverse in (False, True):
                policy, profiles = self.documents()
                values = (
                    profiles["profiles"] if map_name == "profiles" else policy[map_name]
                )
                name = next(iter(values))
                original = copy.deepcopy(values[name])
                # A raw-object ordering rewrite must never choose an alternate control.
                alternate = (
                    original
                    if map_name == "profiles"
                    else (
                        "allow"
                        if map_name == "entity_actions"
                        else []
                        if isinstance(original, list)
                        else 0
                    )
                )
                collision = name.lower() if map_name == "entity_actions" else " " + name
                values[collision] = alternate
                if reverse:
                    reversed_values = dict(reversed(tuple(values.items())))
                    if map_name == "profiles":
                        profiles["profiles"] = reversed_values
                    else:
                        policy[map_name] = reversed_values
                with (
                    self.subTest(map=map_name, reverse=reverse),
                    self.assertRaisesRegex(
                        app.ConfigurationError, "colliding identifiers"
                    ),
                ):
                    self.load_documents(policy, profiles)

    def test_entity_action_whitespace_collisions_are_rejected(self):
        policy, profiles = self.documents()
        name = next(iter(policy["entity_actions"]))
        policy["entity_actions"][" " + name + " "] = "allow"
        with self.assertRaisesRegex(app.ConfigurationError, "colliding identifiers"):
            self.load_documents(policy, profiles)

    def test_accepted_object_permutations_preserve_semantics_and_existing_digest(self):
        policy, profiles = self.documents()
        initial = self.load_documents(policy, profiles)

        def reverse_objects(value):
            if isinstance(value, dict):
                return {
                    key: reverse_objects(item)
                    for key, item in reversed(tuple(value.items()))
                }
            if isinstance(value, list):
                return [reverse_objects(item) for item in value]
            return value

        reordered = self.load_documents(
            reverse_objects(policy), reverse_objects(profiles)
        )
        self.assertEqual(asdict(initial), asdict(reordered))
        expected = app._sha256_bytes(
            app._canonical_json({"policy": policy, "profiles": profiles})
        )
        self.assertEqual(initial.digest, expected)
        policy["blocked_terms"].append("additional synthetic blocked phrase")
        self.assertNotEqual(
            initial.digest, self.load_documents(policy, profiles).digest
        )
