#!/usr/bin/env python3
"""Run deterministic, offline, synthetic adoption fixtures."""

from __future__ import annotations

import contextlib
import importlib.util
import json
import socket
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import patch

FIXTURE_PATH = Path(__file__).with_name("sanitized_demo_cases.json")
CONTAINMENT_ACTIONS = {"queue_for_review", "escalate", "block"}
DEMO_PRIVACY_KEY = b"sanitized-demo-privacy-key-material"


def _load_runtime() -> ModuleType:
    """Load the installed package, or the adjacent one-file source checkout."""
    try:
        from bedrock_guardrail_firewall import orchestrator as installed_runtime

        return installed_runtime
    except ModuleNotFoundError as exc:
        if exc.name != "bedrock_guardrail_firewall":
            raise

    runtime_path = Path(__file__).resolve().parents[1] / "orchestrator.py"
    spec = importlib.util.spec_from_file_location(
        "bedrock_guardrail_firewall_demo_runtime", runtime_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load the local guardrail runtime")
    source_runtime = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = source_runtime
    try:
        spec.loader.exec_module(source_runtime)
    except Exception:
        sys.modules.pop(spec.name, None)
        raise
    return source_runtime


class NetworkAccessDenied(RuntimeError):
    """Raised when the offline demo detects a networking attempt."""


class NetworkGuard:
    """Deny evaluation-time socket creation, connections, and name resolution."""

    def __init__(self) -> None:
        self.operations: list[str] = []
        self._patches = contextlib.ExitStack()

    def _deny(self, operation: str):
        def denied(*args: Any, **kwargs: Any) -> None:
            del args, kwargs
            self.operations.append(operation)
            raise NetworkAccessDenied(f"Offline demo denied {operation}")

        return denied

    def __enter__(self) -> NetworkGuard:
        for operation in (
            "socket",
            "create_connection",
            "getaddrinfo",
            "gethostbyname",
            "gethostbyname_ex",
            "gethostbyaddr",
            "getnameinfo",
            "getfqdn",
        ):
            self._patches.enter_context(
                patch.object(socket, operation, self._deny(operation))
            )
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self._patches.close()


def load_cases() -> list[dict[str, Any]]:
    document = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    cases = document.get("cases")
    if document.get("schema_version") != 1 or not isinstance(cases, list) or not cases:
        raise ValueError("Unsupported sanitized demo fixture")
    return cases


def _fixed_config(runtime: ModuleType, data_dir: Path):
    """Create a configuration that cannot inherit ambient deployment settings."""
    policy_dir = Path(runtime.__file__).resolve().parent
    return runtime.RuntimeConfig(
        policy_path=policy_dir / "guardrail_policy.json",
        profiles_path=policy_dir / "guardrail_policy_profiles.json",
        data_dir=data_dir,
        profile_name="offline_test",
        enforcement_mode="enforce",
        presidio_mode="disabled",
        presidio_model="en_core_web_sm",
        aws_mode="disabled",
        aws_region="us-gov-west-1",
        aws_guardrail_id="",
        aws_guardrail_version="",
        audit_bucket="",
        audit_s3_kms_key_id="",
        audit_signing_key_id="",
        audit_signing_algorithm="RSASSA_PSS_SHA_256",
        audit_signature_required=False,
        audit_object_lock=False,
        audit_retention_days=1,
        remote_audit_required=False,
        review_queue_l1="",
        review_queue_l2="",
        review_queue_l3="",
        remote_review_required=False,
        max_input_chars=32_768,
        max_output_chars=32_768,
        max_context_chars=65_536,
        behavior_retention_days=1,
        behavior_max_subjects=10,
        expected_policy_sha256="",
    )


def _iter_strings(value: Any):
    if isinstance(value, str):
        if value:
            yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_strings(item)


def _containment_values(case: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for field in ("user_input", "candidate_output", "user_context"):
        values.extend(_iter_strings(case.get(field, "")))
    return values


def run() -> dict[str, Any]:
    cases = load_cases()
    runtime = _load_runtime()
    results: list[dict[str, Any]] = []
    raw_release_attempts: list[str] = []
    network_guard = NetworkGuard()
    with (
        tempfile.TemporaryDirectory(prefix="guardrail-sanitized-demo-") as data_dir,
        network_guard,
    ):
        config = _fixed_config(runtime, Path(data_dir))
        config.validate()
        system = runtime.BedrockGuardrailSystem(config, privacy_key=DEMO_PRIVACY_KEY)
        for case in cases:
            try:
                result = system.process(
                    case["user_input"],
                    case.get("user_context", {}),
                    case.get("candidate_output", ""),
                    record=False,
                )
            except NetworkAccessDenied as exc:
                results.append(
                    {
                        "id": case["id"],
                        "evaluation_error": type(exc).__name__,
                        "expected_match": False,
                        "contained": False if case["requires_containment"] else None,
                    }
                )
                continue

            recommended_action = result["recommended_action"]
            expected_match = recommended_action in case["expected_actions"]
            contained = None
            if case["requires_containment"]:
                release_violation = (
                    result.get("content_released") is not False
                    or result.get("sanitized_input") != ""
                    or result.get("sanitized_output") != ""
                )
                contained = (
                    recommended_action in CONTAINMENT_ACTIONS and not release_violation
                )
                if release_violation:
                    raw_release_attempts.append(case["id"])

            # Deliberately omit all content fields. Containment-case raw values must
            # never be serialized, including when a regressed runtime releases them.
            results.append(
                {
                    "id": case["id"],
                    "recommended_action": recommended_action,
                    "risk_level": result["risk_level"],
                    "expected_match": expected_match,
                    "contained": contained,
                    "content_released": bool(result["content_released"]),
                    "detection_categories": sorted(
                        {item["category"] for item in result["detections"]}
                    ),
                }
            )

    containment_results = [
        item["contained"] for item in results if item["contained"] is not None
    ]
    matched = sum(item["expected_match"] for item in results)
    contained = sum(item is True for item in containment_results)
    report: dict[str, Any] = {
        "network_enforcement": {
            "enabled": True,
            "blocked_attempts": len(network_guard.operations),
            "operations": sorted(set(network_guard.operations)),
        },
        "raw_release_attempt_case_ids": sorted(raw_release_attempts),
        "expected_decisions": {
            "passed": matched,
            "total": len(results),
            "rate": matched / len(results),
        },
        "high_risk_containment": {
            "passed": contained,
            "total": len(containment_results),
            "rate": contained / len(containment_results),
        },
        "results": results,
    }
    serialized_report = json.dumps(report, sort_keys=True)
    leaked_case_ids = sorted(
        {
            case["id"]
            for case in cases
            if case["requires_containment"]
            and any(value in serialized_report for value in _containment_values(case))
        }
    )
    network_attempts = len(network_guard.operations)
    success = (
        matched == len(results)
        and contained == len(containment_results)
        and not raw_release_attempts
        and not leaked_case_ids
        and network_attempts == 0
        and all("evaluation_error" not in item for item in results)
    )
    report.update(
        {
            "success": success,
            "raw_high_risk_values_emitted": bool(leaked_case_ids),
            "raw_high_risk_leak_case_ids": leaked_case_ids,
        }
    )
    return report


def main() -> int:
    report = run()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
