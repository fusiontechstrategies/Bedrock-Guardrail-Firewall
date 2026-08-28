#!/usr/bin/env python3
"""Validate the installed distribution without trusting the source checkout."""

from __future__ import annotations

import argparse
import json
import socket
import tempfile
from importlib import metadata, resources
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_NAME = "bedrock-guardrail-firewall"
EXPECTED_VERSION = "4.1.0"
EXPECTED_REQUIRES_DIST = {
    'boto3==1.43.79; extra == "aws"',
    'botocore==1.43.79; extra == "aws"',
    'presidio-analyzer==2.2.364; python_version < "3.14" and extra == "presidio"',
    'spacy==3.8.16; python_version < "3.14" and extra == "presidio"',
}
EXPECTED_RESOURCES = {
    "__init__.py",
    "guardrail_policy.json",
    "guardrail_policy_profiles.json",
    "orchestrator.py",
    "py.typed",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def validate_metadata() -> None:
    document = metadata.metadata(PROJECT_NAME)
    actual_requirements = set(document.get_all("Requires-Dist") or [])
    require(document["Name"] == PROJECT_NAME, "Unexpected distribution name")
    require(
        document["Version"] == EXPECTED_VERSION,
        "Distribution version is not the expected release version",
    )
    require(document["License-Expression"] == "Apache-2.0", "License mismatch")
    require(
        set(document.get_all("Provides-Extra") or []) == {"aws", "presidio"},
        "Optional dependency groups changed",
    )
    require(
        actual_requirements == EXPECTED_REQUIRES_DIST,
        f"Requires-Dist mismatch: {sorted(actual_requirements)!r}",
    )


def validate_resources():
    package_root = resources.files("bedrock_guardrail_firewall")
    actual_files = {item.name for item in package_root.iterdir() if item.is_file()}
    require(
        actual_files == EXPECTED_RESOURCES, f"Package files changed: {actual_files!r}"
    )
    for name in EXPECTED_RESOURCES:
        require(
            package_root.joinpath(name).is_file(), f"Missing package resource: {name}"
        )
    for name in ("guardrail_policy.json", "guardrail_policy_profiles.json"):
        with package_root.joinpath(name).open("r", encoding="utf-8") as handle:
            require(
                isinstance(json.load(handle), dict), f"Invalid JSON resource: {name}"
            )
    return package_root


def make_config(runtime, package_root, data_dir: Path, **overrides):
    settings = {
        "policy_path": Path(str(package_root.joinpath("guardrail_policy.json"))),
        "profiles_path": Path(
            str(package_root.joinpath("guardrail_policy_profiles.json"))
        ),
        "data_dir": data_dir,
        "profile_name": "offline_test",
        "presidio_mode": "disabled",
        "aws_mode": "disabled",
    }
    settings.update(overrides)
    return runtime.RuntimeConfig(**settings)


def validate_core(runtime, package_root) -> None:
    require(runtime.__version__ == EXPECTED_VERSION, "Runtime version mismatch")
    with tempfile.TemporaryDirectory(prefix="guardrail-package-core-") as directory:
        config = make_config(runtime, package_root, Path(directory))
        system = runtime.BedrockGuardrailSystem(
            config, privacy_key=b"installed-package-validation-key-0001"
        )
        require(system.doctor()["ready"], "Installed offline core is not ready")


def validate_missing_presidio_model(runtime, package_root) -> None:
    require(runtime.PRESIDIO_AVAILABLE, "Presidio extra is not installed")
    require(
        not runtime.spacy.util.is_package("en_core_web_sm"),
        "Missing-model check requires an environment without en_core_web_sm",
    )
    provider = MagicMock(name="NlpEngineProvider")
    with tempfile.TemporaryDirectory(prefix="guardrail-package-presidio-") as directory:
        config = make_config(
            runtime,
            package_root,
            Path(directory),
            profile_name="balanced",
            presidio_mode="required",
            presidio_model="en_core_web_sm",
        )
        with (
            patch.object(runtime, "NlpEngineProvider", provider),
            patch.object(runtime.spacy.cli, "download") as download,
            patch.object(socket, "socket") as socket_constructor,
            patch.object(socket, "create_connection") as connection,
            patch.object(socket, "getaddrinfo") as name_resolution,
        ):
            system = runtime.BedrockGuardrailSystem(
                config, privacy_key=b"installed-package-validation-key-0001"
            )
            report = system.doctor()
        check = next(
            item for item in report["checks"] if item["name"] == "presidio_engine"
        )
        require(not report["ready"], "Missing Presidio model passed readiness")
        require(check["status"] == "fail", "Missing model was not release-blocking")
        require(
            check["detail"] == "presidio_model_unavailable",
            "Missing model produced an unexpected diagnostic",
        )
        require(not provider.called, "Presidio provider ran before model preflight")
        require(not download.called, "spaCy model download was invoked")
        require(not socket_constructor.called, "A network socket was created")
        require(not connection.called, "A network connection was attempted")
        require(not name_resolution.called, "Network name resolution was attempted")


def validate_presidio(runtime, package_root) -> None:
    require(runtime.PRESIDIO_AVAILABLE, "Presidio extra is not installed")
    require(
        runtime.spacy.util.is_package("en_core_web_sm"),
        "Pinned Presidio language model is not installed",
    )
    with tempfile.TemporaryDirectory(prefix="guardrail-package-presidio-") as directory:
        config = make_config(
            runtime,
            package_root,
            Path(directory),
            profile_name="balanced",
            presidio_mode="required",
            presidio_model="en_core_web_sm",
        )
        system = runtime.BedrockGuardrailSystem(
            config, privacy_key=b"installed-package-validation-key-0001"
        )
        report = system.doctor()
        check = next(
            item for item in report["checks"] if item["name"] == "presidio_engine"
        )
        require(report["ready"], "Installed Presidio package is not ready")
        require(check["status"] == "pass", "Presidio engine did not initialize")
        result = system.privacy.evaluate(
            "Connect from documentation address 192.0.2.10.", "input"
        )
        finding = next(
            (
                item
                for item in result.findings
                if item.entity_type == "IP_ADDRESS" and item.recognizer == "presidio"
            ),
            None,
        )
        require(finding is not None, "Presidio did not detect the test IP address")
        require(
            "192.0.2.10" not in result.sanitized_text,
            "Presidio finding was not irreversibly redacted",
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("core", "missing-presidio-model", "presidio"))
    arguments = parser.parse_args()

    from bedrock_guardrail_firewall import orchestrator as runtime

    validate_metadata()
    package_root = validate_resources()
    if arguments.mode == "core":
        validate_core(runtime, package_root)
    elif arguments.mode == "missing-presidio-model":
        validate_missing_presidio_model(runtime, package_root)
    else:
        validate_presidio(runtime, package_root)
    print(f"Installed package validation passed: {arguments.mode}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
