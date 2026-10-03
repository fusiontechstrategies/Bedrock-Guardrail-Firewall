from __future__ import annotations

import base64
import csv
import ctypes
import hashlib
import io
import json
import os
import tarfile
import unittest
from tests.private_state_fixture import PrivateTemporaryDirectory
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, patch

import orchestrator as app
from scripts import normalize_sdist as normalizer
from scripts import prepare_release_evidence as release
from tests.test_orchestrator import (
    FakeBedrockClient,
    GuardrailTestCase,
    RecordingClient,
)
from tests import test_release_evidence as release_tests

METADATA = release_tests.METADATA
VERSION = release_tests.VERSION

TOKEN = "vU8_z4R0-6mq~B3n9+TWJk/Qp7Ha0eSx2Y="


class OpaqueCredentialTests(GuardrailTestCase):
    def test_tokens_are_contained_on_all_routes_with_block_and_sanitize_policies(self):
        for action in (app.GuardrailAction.BLOCK, app.GuardrailAction.SANITIZE):
            for prefix in (
                "access_token=",
                "?access_token=",
                "refresh_token=",
                "Bearer ",
                "Authorization: Bearer ",
                '"ACCESS_TOKEN": "',
            ):
                for route in ("input", "output", "retrieval"):
                    with self.subTest(action=action, prefix=prefix, route=route):
                        client = FakeBedrockClient()
                        system = self.make_live_system(client)
                        system.privacy.bundle = replace(
                            system.bundle,
                            entity_actions={
                                **system.bundle.entity_actions,
                                "OPAQUE_TOKEN": action,
                            },
                        )
                        user_input = "Write a short summary."
                        output = "A short approved summary."
                        context = {
                            "retrieval_contexts": [{"id": "doc", "text": output}]
                        }
                        baseline = system.process(
                            user_input, context, output, record=False
                        )
                        self.assertTrue(baseline["content_released"])
                        self.assertTrue(client.calls)
                        client.calls.clear()
                        labelled = " " + prefix + TOKEN + ('"' if '"' in prefix else "")
                        if route == "input":
                            user_input += labelled
                        elif route == "output":
                            output += labelled
                            context["retrieval_contexts"][0]["text"] = output
                        else:
                            context["retrieval_contexts"][0]["text"] += labelled
                        result = system.process(
                            user_input, context, output, record=False
                        )
                        self.assertNotIn(TOKEN, json.dumps(result))
                        self.assertNotIn(TOKEN, json.dumps(client.calls))
                        if action == app.GuardrailAction.BLOCK:
                            self.assertFalse(result["content_released"])
                        else:
                            self.assertTrue(
                                client.calls,
                                "The sanitized AWS route was not exercised",
                            )

    def test_normalization_contains_obfuscated_labels_and_values(self):
        system = self.make_system()
        for text in (
            "access_\u200btoken=" + TOKEN,
            "Ｂｅａｒｅｒ " + TOKEN,
            "ＡＣＣＥＳＳ＿ＴＯＫＥＮ＝" + TOKEN,
            "refresh_token=" + TOKEN[:9] + "\u200b" + TOKEN[9:],
        ):
            with self.subTest(text=text):
                result = system.privacy.evaluate(text, "input")
                self.assertNotIn(TOKEN, result.sanitized_text)
                self.assertTrue(
                    any(x.entity_type == "OPAQUE_TOKEN" for x in result.findings)
                )

    def test_length_and_candidate_budgets_fail_before_cloud(self):
        client = FakeBedrockClient()
        system = self.make_live_system(client)
        valid = system.privacy.evaluate("access_token=" + "x" * 4096, "input")
        self.assertNotIn("x" * 4096, valid.sanitized_text)
        self.assertEqual(
            len(system.privacy._regex_findings("access_token=x " * 64)), 64
        )
        for text in (
            "access_token=" + "x" * 4097,
            "Authorization: Bearer x " * 65,
            "access_token=abc%2Fdef",
            "refresh_token=abc\\def",
            "Authorization: Bearer abc@def",
        ):
            with self.subTest(text=text[:80]):
                with self.assertRaises(app.InputValidationError):
                    system.process(text, {}, record=False)
                self.assertFalse(client.calls)

    def test_plain_text_and_exact_placeholders_remain_controls(self):
        system = self.make_system()
        controls = ["documentation.example.invalid", "ordinary unrelated prose"]
        controls.extend("Bearer " + item for item in app.OPAQUE_TOKEN_PLACEHOLDERS)
        controls.extend(
            "access_token=" + item.upper() for item in app.OPAQUE_TOKEN_PLACEHOLDERS
        )
        for text in controls:
            with self.subTest(text=text):
                result = system.privacy.evaluate(text, "input")
                self.assertEqual(result.sanitized_text, text)
                self.assertFalse(result.findings)

    def test_labelled_padded_jose_values_preserve_full_span_and_jwt_policy(self):
        token = ".".join(
            base64.urlsafe_b64encode(value).decode()
            for value in (b'{"alg":"HS256","pad":0}', b"x", b"synthetic")
        )
        self.assertIn("=", token)
        self.assertTrue(app._jwt_credential_like(token))
        for route in ("input", "output", "retrieval"):
            with self.subTest(route=route):
                client = FakeBedrockClient()
                system = self.make_live_system(client)
                system.privacy.bundle = replace(
                    system.bundle,
                    entity_actions={
                        **system.bundle.entity_actions,
                        "JWT": app.GuardrailAction.SANITIZE,
                        "OPAQUE_TOKEN": app.GuardrailAction.BLOCK,
                    },
                )
                text = "Bearer " + token
                user_input, output = "Write a short summary.", "Approved summary."
                context = {"retrieval_contexts": [{"id": "doc", "text": output}]}
                if route == "input":
                    user_input += " " + text
                elif route == "output":
                    output += " " + text
                    context["retrieval_contexts"][0]["text"] = output
                else:
                    context["retrieval_contexts"][0]["text"] += " " + text
                findings = system.privacy._regex_findings(text)
                self.assertTrue(
                    any(
                        item.entity_type == "JWT"
                        and item.action == app.GuardrailAction.SANITIZE
                        and text[item.start : item.end] == token
                        for item in findings
                    )
                )
                result = system.process(user_input, context, output, record=False)
                self.assertNotIn(token, json.dumps(result))
                self.assertTrue(client.calls)
                self.assertNotIn(token, json.dumps(client.calls))

    def test_natural_bearer_prose_remains_unchanged_on_every_content_route(self):
        for phrase in ("bearer bonds", "bearer shares", "bearer plant"):
            for route in ("input", "output", "retrieval"):
                with self.subTest(phrase=phrase, route=route):
                    client = FakeBedrockClient()
                    system = self.make_live_system(client)
                    text = "Explain " + phrase + "."
                    privacy = system.privacy.evaluate(text, route)
                    self.assertEqual(privacy.sanitized_text, text)
                    self.assertFalse(privacy.findings)
                    user_input, output = "Write a short summary.", text
                    context = {"retrieval_contexts": [{"id": "doc", "text": output}]}
                    if route == "input":
                        user_input = text
                    result = system.process(user_input, context, output, record=False)
                    self.assertTrue(result["content_released"])
                    self.assertTrue(client.calls)
                    self.assertIn(phrase, json.dumps(client.calls))

    def test_explicit_short_credentials_and_bare_length_boundary(self):
        system = self.make_system()
        for prefix in (
            "access_token=",
            "refresh_token=",
            "Authorization: Bearer ",
            '"Authorization": "Bearer ',
            "Ａｕｔｈｏｒｉｚａｔｉｏｎ： Ｂｅａｒｅｒ ",
        ):
            with self.subTest(prefix=prefix):
                result = system.privacy.evaluate(prefix + "a7", "input")
                self.assertNotIn("a7", result.sanitized_text)
                self.assertTrue(
                    any(x.entity_type == "OPAQUE_TOKEN" for x in result.findings)
                )
        self.assertFalse(
            system.privacy.evaluate("Bearer " + "a" * 15, "input").findings
        )
        self.assertTrue(system.privacy.evaluate("Bearer " + "a" * 16, "input").findings)

    def test_excluded_prose_and_placeholders_do_not_exhaust_credential_budget(self):
        client = FakeBedrockClient()
        system = self.make_live_system(client)
        prose = "Explain bearer bonds. Bearer token refresh_token=redacted " * 80
        result = system.privacy.evaluate(prose, "input")
        self.assertEqual(result.sanitized_text, prose)
        self.assertFalse(result.findings)
        self.assertEqual(
            len(system.privacy._regex_findings(prose + "access_token=x " * 64)), 64
        )
        with self.assertRaisesRegex(app.InputValidationError, "candidate budget"):
            system.process(prose + "Authorization: Bearer x " * 65, {}, record=False)
        self.assertFalse(client.calls)


def change_wheel_metadata(wheel: Path, metadata: bytes) -> None:
    with zipfile.ZipFile(wheel) as archive:
        values = {name: archive.read(name) for name in archive.namelist()}
    metadata_name = next(name for name in values if name.endswith("/METADATA"))
    record_name = next(name for name in values if name.endswith("/RECORD"))
    values[metadata_name] = metadata
    rows = io.StringIO(newline="")
    writer = csv.writer(rows, lineterminator="\n")
    for name, value in sorted(values.items()):
        if name == record_name:
            continue
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(value).digest())
            .rstrip(b"=")
            .decode()
        )
        writer.writerow([name, "sha256=" + digest, len(value)])
    writer.writerow([record_name, "", ""])
    values[record_name] = rows.getvalue().encode()
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, value in values.items():
            archive.writestr(release_tests.canonical_wheel_info(name), value)


class MarkerAndArchiveTests(unittest.TestCase):
    def fixture(self, root):
        helper = release_tests.ReleaseEvidenceTests()
        helper.make_source(root)
        helper.make_distributions(root / "dist")
        return next((root / "dist").glob("*.whl"))

    def test_self_consistent_wheels_reject_broadened_or_incomplete_markers(self):
        attacks = (
            ('extra == "aws"', 'extra == "aws" or extra != "aws"'),
            ('extra == "aws"', 'extra == "aws" or python_version >= "3"'),
            ('extra == "aws"', 'extra == "aws" and extra == "aws"'),
            ('extra == "aws"', 'extra == "aws" and os_name == "nt"'),
            ('python_version < "3.14" and extra == "presidio"', 'extra == "presidio"'),
            (
                'python_version < "3.14" and extra == "presidio"',
                'python_version <= "3.14" and extra == "presidio"',
            ),
            (
                'python_version < "3.14" and extra == "presidio"',
                '"3.14" < python_version and extra == "presidio"',
            ),
            ('extra == "aws"', 'extra == "aws" and (extra == "aws" or extra != "aws")'),
        )
        for old, new in attacks:
            with self.subTest(marker=new), PrivateTemporaryDirectory() as directory:
                root = Path(directory)
                wheel = self.fixture(root)
                change_wheel_metadata(
                    wheel, METADATA.replace(old.encode(), new.encode())
                )
                with self.assertRaises(release.ReleaseEvidenceError):
                    release.validate_wheel(
                        wheel, VERSION, release.parse_optional_dependencies(root), root
                    )

    def test_marker_equivalents_parse_but_source_divergent_bytes_are_refused(self):
        with PrivateTemporaryDirectory() as directory:
            root = Path(directory)
            wheel = self.fixture(root)
            metadata = METADATA.replace(b'extra == "aws"', b"((extra=='aws'))")
            metadata = metadata.replace(
                b'python_version < "3.14" and extra == "presidio"',
                b'("presidio" == extra) and ("3.14" > python_version)',
            )
            change_wheel_metadata(wheel, metadata)
            actual = release.parse_wheel_dependencies(
                release.parse_metadata(metadata, wheel.name)
            )
            with self.assertRaisesRegex(
                release.ReleaseEvidenceError, "differs from reviewed source"
            ):
                release.validate_wheel(
                    wheel, VERSION, release.parse_optional_dependencies(root), root
                )
            self.assertEqual(len(actual), 4)
            self.assertIn(
                'extra == "presidio" and python_version < "3.14"',
                {x["marker"] for x in actual},
            )

    def test_source_metadata_and_parser_work_budgets_are_authenticated(self):
        with PrivateTemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            path = root / "pyproject.toml"
            path.write_text(path.read_text().replace("3.14", "3.13"))
            with self.assertRaises(release.ReleaseEvidenceError):
                release.parse_optional_dependencies(root)
        for requirement in (
            "x" * 1025,
            "pkg==1; " + "(" * 600 + 'extra == "aws"' + ")" * 600,
        ):
            with (
                self.subTest(requirement=requirement[:40]),
                self.assertRaises(release.ReleaseEvidenceError),
            ):
                release.pinned_requirement(requirement)

    def test_short_names_are_refused_at_all_archive_boundaries(self):
        aliases = (
            "pyproj~1.tom",
            "setup~1.py",
            "setupc~1.cfg",
            "bedroc~1/orches~1.py",
            "DISTIN~1/METADATA",
            "notes~123.md",
        )
        for alias in aliases:
            with self.subTest(alias=alias):
                with self.assertRaisesRegex(release.ReleaseEvidenceError, "short-name"):
                    release.archive_parts("package/" + alias)
                with self.assertRaisesRegex(
                    normalizer.SdistNormalizationError, "short-name"
                ):
                    normalizer.validate_member_name("package/" + alias)
        for name in ("package/pyproject.toml", "package/notes~draft.md"):
            self.assertTrue(release.archive_parts(name))
            normalizer.validate_member_name(name)

    def test_real_archives_reject_aliases_before_verification_or_normalization(self):
        with PrivateTemporaryDirectory() as directory:
            root = Path(directory)
            wheel = self.fixture(root)
            with zipfile.ZipFile(wheel, "a") as archive:
                archive.writestr("bedroc~1/orchestrator.py", b"unreviewed")
            with self.assertRaisesRegex(release.ReleaseEvidenceError, "short-name"):
                release.validate_wheel(
                    wheel, VERSION, release.parse_optional_dependencies(root), root
                )
            sdist = next((root / "dist").glob("*.tar.gz"))
            with tarfile.open(sdist, "r:gz") as archive:
                entries = [
                    (
                        member,
                        archive.extractfile(member).read() if member.isfile() else None,
                    )
                    for member in archive.getmembers()
                ]
            with tarfile.open(sdist, "w:gz") as archive:
                for member, value in entries:
                    archive.addfile(
                        member, io.BytesIO(value) if value is not None else None
                    )
                member = tarfile.TarInfo(
                    f"bedrock_guardrail_firewall-{VERSION}/pyproj~1.tom"
                )
                member.size = 10
                archive.addfile(member, io.BytesIO(b"unreviewed"))
            before = sdist.read_bytes()
            with self.assertRaisesRegex(release.ReleaseEvidenceError, "short-name"):
                release.validate_sdist(sdist, VERSION, root)
            with self.assertRaisesRegex(
                normalizer.SdistNormalizationError, "short-name"
            ):
                normalizer.normalize_sdist(sdist, 315532800)
            self.assertEqual(sdist.read_bytes(), before)

    @unittest.skipUnless(os.name == "nt", "Windows alias observation only")
    def test_observed_windows_alias_is_refused_without_settings_changes(
        self,
    ):
        with PrivateTemporaryDirectory() as directory:
            path = Path(directory) / "pyproject.toml"
            path.write_bytes(b"reviewed build configuration")
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            query = kernel.GetShortPathNameW
            query.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
            query.restype = ctypes.c_uint32
            buffer = ctypes.create_unicode_buffer(32768)
            length = query(str(path), buffer, len(buffer))
            self.assertGreater(length, 0)
            alias = Path(buffer.value)
            if "~" not in alias.name:
                self.skipTest(
                    "Fixture volume did not create an 8.3 alias; "
                    "lexical guard still tested"
                )
            self.assertEqual(alias.read_bytes(), path.read_bytes())
            with self.assertRaisesRegex(release.ReleaseEvidenceError, "short-name"):
                release.archive_parts("package/" + alias.name)
            # Demonstrate the platform collision only in this owned inert fixture.
            # No source/configuration is executed and no filesystem setting changes.
            payload = b"synthetic alias overwrite"
            buffer_archive = io.BytesIO()
            with tarfile.open(fileobj=buffer_archive, mode="w") as archive:
                member = tarfile.TarInfo(alias.name)
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            buffer_archive.seek(0)
            with tarfile.open(fileobj=buffer_archive, mode="r") as archive:
                # This archive has exactly one owned, inert, OS-observed member;
                # extract that member with the API supported on Python 3.10.
                archive.extract(alias.name, path.parent)
            self.assertEqual(path.read_bytes(), payload)


class LambdaDurableAuditTests(GuardrailTestCase):
    def setUp(self):
        previous = app._LAMBDA_SYSTEM
        app._LAMBDA_SYSTEM = None
        self.addCleanup(setattr, app, "_LAMBDA_SYSTEM", previous)

    def environment(self, directory, **overrides):
        return {
            "GUARDRAIL_DATA_DIR": str(directory),
            "GUARDRAIL_PRESIDIO_MODE": "disabled",
            "GUARDRAIL_REMOTE_AUDIT_REQUIRED": "true",
            "GUARDRAIL_AUDIT_BUCKET": "synthetic-audit",
            "GUARDRAIL_AWS_MODE": "live",
            "GUARDRAIL_PRIVACY_HMAC_KEY_B64": base64.urlsafe_b64encode(
                b"synthetic-key-for-lambda-test-12345"
            ).decode(),
            **overrides,
        }

    def test_cold_start_refuses_missing_durable_requirements_before_any_client(self):
        for overrides in (
            {"GUARDRAIL_REMOTE_AUDIT_REQUIRED": "false"},
            {"GUARDRAIL_REMOTE_AUDIT_REQUIRED": ""},
            {"GUARDRAIL_AUDIT_BUCKET": ""},
            {"GUARDRAIL_AWS_MODE": "disabled"},
            {"GUARDRAIL_AWS_MODE": "preview"},
            {"GUARDRAIL_PRIVACY_HMAC_KEY_B64": ""},
            {"GUARDRAIL_PRIVACY_HMAC_KEY_B64": "invalid!"},
        ):
            with (
                self.subTest(overrides=overrides),
                PrivateTemporaryDirectory() as directory,
            ):
                with (
                    patch.dict(
                        os.environ, self.environment(directory, **overrides), clear=True
                    ),
                    patch.object(app, "BedrockGuardrailSystem") as constructor,
                ):
                    response = app.lambda_handler(
                        {"body": {"user_input": "safe input"}}, None
                    )
                self.assertEqual(response["statusCode"], 503)
                self.assertEqual(
                    json.loads(response["body"])["error"], "configuration_error"
                )
                constructor.assert_not_called()
                self.assertIsNone(app._LAMBDA_SYSTEM)

    def test_malformed_cold_events_cannot_bypass_startup_gate(self):
        events = (
            None,
            [],
            {"body": "{"},
            {"body": "[]"},
            {"body": '{"user_input":"a","user_input":"b"}'},
            {"body": {"user_input": "safe", "record": False}},
            {"body": {"user_input": "safe", "remote_audit_required": False}},
            {"body": {"user_input": "safe", "user_context": []}},
            {"body": "invalid!", "isBase64Encoded": True},
            {"body": [], "isBase64Encoded": True},
        )
        for event in events:
            with self.subTest(event=event):
                with (
                    patch.object(
                        app.RuntimeConfig,
                        "from_lambda_env",
                        side_effect=app.ConfigurationError("synthetic missing profile"),
                    ) as gate,
                    patch.object(app, "BedrockGuardrailSystem") as constructor,
                ):
                    response = app.lambda_handler(event, None)
                self.assertEqual(response["statusCode"], 503)
                gate.assert_called_once_with()
                constructor.assert_not_called()
                self.assertIsNone(app._LAMBDA_SYSTEM)
        with PrivateTemporaryDirectory() as directory:
            for event in events:
                with (
                    self.subTest(valid_profile_event=event),
                    patch.dict(os.environ, self.environment(directory), clear=True),
                    patch.object(
                        app.RuntimeConfig,
                        "from_lambda_env",
                        wraps=app.RuntimeConfig.from_lambda_env,
                    ) as gate,
                    patch.object(app, "BedrockGuardrailSystem") as constructor,
                ):
                    response = app.lambda_handler(event, None)
                    self.assertEqual(response["statusCode"], 400)
                    gate.assert_called_once_with()
                    constructor.assert_not_called()

    def test_valid_cold_start_passes_required_profile_and_body_cannot_override_it(self):
        with PrivateTemporaryDirectory() as directory:
            system = MagicMock()
            system.process.return_value = {"action": "allow"}
            with (
                patch.dict(os.environ, self.environment(directory), clear=True),
                patch.object(
                    app, "BedrockGuardrailSystem", return_value=system
                ) as constructor,
            ):
                response = app.lambda_handler(
                    {
                        "body": {
                            "user_input": "safe",
                            "user_context": {"remote_audit_required": False},
                        }
                    },
                    None,
                )
            self.assertEqual(response["statusCode"], 200)
            self.assertTrue(constructor.call_args.args[0].remote_audit_required)
            self.assertEqual(
                constructor.call_args.args[0].audit_bucket, "synthetic-audit"
            )
            self.assertEqual(constructor.call_args.args[0].aws_mode, "live")
            self.assertNotIn("remote_audit_required", system.process.call_args.args[1])
            response = app.lambda_handler(
                {"body": {"user_input": "safe", "remote_audit_required": False}}, None
            )
            self.assertEqual(response["statusCode"], 400)

    def test_remote_delivery_failure_blocks_lambda_content_and_no_record_bypass_exists(
        self,
    ):
        system = self.make_live_system(
            FakeBedrockClient(),
            audit_bucket="synthetic-audit",
            remote_audit_required=True,
        )
        system.provider._clients["s3"] = RecordingClient(
            failure=TimeoutError("synthetic")
        )
        with (
            patch.object(
                app.RuntimeConfig, "from_lambda_env", return_value=system.config
            ),
            patch.object(app, "BedrockGuardrailSystem", return_value=system),
        ):
            response = app.lambda_handler(
                {"body": {"user_input": "A safe request."}}, None
            )
        body = json.loads(response["body"])
        self.assertEqual(body["action"], "block")
        self.assertFalse(body["content_released"])
        self.assertIn("required_remote_audit_failed", body["diagnostics"])
        with self.assertRaises(app.ConfigurationError):
            system.process("Safe request.", record=False)
