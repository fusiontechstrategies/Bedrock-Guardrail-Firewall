from __future__ import annotations

import json
import importlib.util
import os
import re
import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEMO_PATH = PROJECT_ROOT / "examples" / "run_sanitized_demo.py"
DEMO_SPEC = importlib.util.spec_from_file_location(
    "sanitized_demo_test_runtime", DEMO_PATH
)
if DEMO_SPEC is None or DEMO_SPEC.loader is None:
    raise RuntimeError("Unable to load the sanitized demo")
demo = importlib.util.module_from_spec(DEMO_SPEC)
sys.modules[DEMO_SPEC.name] = demo
DEMO_SPEC.loader.exec_module(demo)


class SanitizedDemoTests(unittest.TestCase):
    @staticmethod
    def load_runtime_for_injection():
        runtime = demo._load_runtime()
        return runtime, patch.object(demo, "_load_runtime", return_value=runtime)

    def test_demo_meets_offline_containment_baseline(self):
        report = demo.run()
        self.assertTrue(report["success"])
        self.assertEqual(report["expected_decisions"]["passed"], 6)
        self.assertEqual(report["high_risk_containment"]["passed"], 4)
        self.assertEqual(report["network_enforcement"]["blocked_attempts"], 0)
        self.assertFalse(report["raw_high_risk_values_emitted"])
        self.assertEqual(report["raw_release_attempt_case_ids"], [])

    def test_demo_ignores_every_guardrail_environment_variable(self):
        source = (PROJECT_ROOT / "orchestrator.py").read_text(encoding="utf-8")
        names = set(re.findall(r"GUARDRAIL_[A-Z0-9_]+", source))
        self.assertGreater(len(names), 10)
        polluted = {name: "<<invalid ambient value>>" for name in names}
        polluted.update(
            {
                "AWS_REGION": "invalid-region",
                "BEDROCK_GUARDRAIL_ID": "ambient-guardrail",
                "BEDROCK_GUARDRAIL_VERSION": "999",
            }
        )
        with patch.dict(os.environ, polluted, clear=False):
            report = demo.run()
        self.assertTrue(report["success"])
        self.assertEqual(report["network_enforcement"]["blocked_attempts"], 0)

    def test_raw_release_regression_fails_without_serializing_payloads(self):
        cases = demo.load_cases()
        containment_inputs = {
            case["user_input"] for case in cases if case["requires_containment"]
        }
        runtime, runtime_loader = self.load_runtime_for_injection()
        original_process = runtime.BedrockGuardrailSystem.process

        def injected_process(
            system,
            user_input,
            caller_context=None,
            candidate_output="",
            *,
            record=True,
            request_id=None,
        ):
            result = original_process(
                system,
                user_input,
                caller_context,
                candidate_output,
                record=record,
                request_id=request_id,
            )
            if user_input in containment_inputs:
                result["content_released"] = True
                result["sanitized_input"] = user_input
                result["sanitized_output"] = candidate_output
            return result

        with (
            patch.object(
                runtime.BedrockGuardrailSystem, "process", new=injected_process
            ),
            runtime_loader,
        ):
            report = demo.run()

        serialized = json.dumps(report, sort_keys=True)
        self.assertFalse(report["success"])
        self.assertEqual(report["high_risk_containment"]["passed"], 0)
        self.assertEqual(len(report["raw_release_attempt_case_ids"]), 4)
        self.assertFalse(report["raw_high_risk_values_emitted"])
        for case in cases:
            if case["requires_containment"]:
                for value in demo._containment_values(case):
                    self.assertNotIn(value, serialized)

    def test_network_attempt_is_actively_denied_and_reported(self):
        runtime, runtime_loader = self.load_runtime_for_injection()

        def injected_network_attempt(*args, **kwargs):
            del args, kwargs
            socket.create_connection(("example.invalid", 443))

        with (
            patch.object(
                runtime.BedrockGuardrailSystem,
                "process",
                new=injected_network_attempt,
            ),
            runtime_loader,
        ):
            report = demo.run()

        self.assertFalse(report["success"])
        self.assertGreater(report["network_enforcement"]["blocked_attempts"], 0)
        self.assertIn("create_connection", report["network_enforcement"]["operations"])

    def test_network_guard_denies_socket_and_resolution_entry_points(self):
        def create_socket():
            return socket.socket()

        attempts = {
            "socket": create_socket,
            "create_connection": lambda: socket.create_connection(
                ("example.invalid", 443)
            ),
            "getaddrinfo": lambda: socket.getaddrinfo("example.invalid", 443),
            "gethostbyname": lambda: socket.gethostbyname("example.invalid"),
            "gethostbyname_ex": lambda: socket.gethostbyname_ex("example.invalid"),
            "gethostbyaddr": lambda: socket.gethostbyaddr("192.0.2.1"),
            "getnameinfo": lambda: socket.getnameinfo(("192.0.2.1", 443), 0),
            "getfqdn": lambda: socket.getfqdn("example.invalid"),
        }

        for operation, attempt in attempts.items():
            with self.subTest(operation=operation):
                guard = demo.NetworkGuard()
                with guard, self.assertRaises(demo.NetworkAccessDenied):
                    attempt()
                self.assertEqual(guard.operations, [operation])


if __name__ == "__main__":
    unittest.main()
