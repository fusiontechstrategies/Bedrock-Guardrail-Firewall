from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import create_verified_draft as draft
from scripts import normalize_sdist
from scripts import prepare_release_evidence as release
from scripts import verify_release_handoff as handoff
from tests import test_release_evidence as fixtures

ROOT = Path(__file__).resolve().parents[1]
COMMIT, TAG = fixtures.COMMIT, fixtures.TAG


class TrustedPromotionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory()
        self.addCleanup(self.fixture.cleanup)
        self.root = Path(self.fixture.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        maker = fixtures.ReleaseEvidenceTests()
        maker.make_source(self.source)
        # Selected Python is authenticated data, never the executing verifier.
        (self.source / "scripts/prepare_release_evidence.py").write_text(
            "raise RuntimeError('selected helper must not execute')\n"
        )
        self.dist = self.source / "dist"
        maker.make_distributions(self.dist)
        normalize_sdist.normalize_sdist(next(self.dist.glob("*.tar.gz")), 315532800)
        self.assets = self.root / "assets"
        release.prepare_release_evidence(
            self.source, self.dist, self.assets, TAG, COMMIT
        )
        for path in self.dist.iterdir():
            shutil.copyfile(path, self.assets / path.name)

    def test_exact_five_assets_use_trusted_static_verifier(self):
        subjects = handoff.verify_handoff(self.assets, self.source, COMMIT, TAG)
        self.assertEqual(subjects["tag"], TAG)
        self.assertEqual(len(subjects["manifest"]), 5)

    def test_changed_source_asset_commit_tag_or_extra_asset_refuse(self):
        for field in ("source", "asset", "commit", "tag", "extra"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                assets, source = root / "assets", root / "source"
                shutil.copytree(self.assets, assets)
                shutil.copytree(self.source, source)
                commit, tag = COMMIT, TAG
                if field == "source":
                    (source / "orchestrator.py").write_text("altered\n")
                elif field == "asset":
                    (assets / "SHA256SUMS.txt").write_text("altered\n")
                elif field == "commit":
                    commit = "b" * 40
                elif field == "tag":
                    tag = "v0.0.0"
                else:
                    (assets / "extra.py").write_text("raise RuntimeError()\n")
                with self.assertRaises((ValueError, RuntimeError)):
                    handoff.verify_handoff(assets, source, commit, tag)

    def test_authenticated_run_binds_all_fields_and_unique_artifact(self):
        run = dict(
            id=123,
            path=".github/workflows/release-candidate.yml",
            event="repository_dispatch",
            conclusion="success",
            head_sha=COMMIT,
            head_repository={"full_name": "owner/repository"},
            head_branch="main",
        )
        pages = [{"artifacts": [dict(id=456, name="release-assets", expired=False)]}]
        self.assertEqual(
            handoff.verify_run_identity(run, pages, 123, COMMIT, "owner/repository")[
                "artifact-id"
            ],
            456,
        )
        for key, replacement in [
            ("id", 999),
            ("path", ".github/workflows/evil.yml"),
            ("event", "push"),
            ("conclusion", "failure"),
            ("head_sha", "b" * 40),
            ("head_branch", TAG),
            ("head_repository", {"full_name": "attacker/fork"}),
        ]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                handoff.verify_run_identity(
                    dict(run, **{key: replacement}),
                    pages,
                    123,
                    COMMIT,
                    "owner/repository",
                )
        with self.assertRaises(ValueError):
            handoff.verify_run_identity(
                run, pages + pages, 123, COMMIT, "owner/repository"
            )

    def test_isolated_cli_cannot_import_selected_json_or_helper(self):
        marker = self.root / "shadow-executed"
        (self.source / "json.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('unsafe')\n"
        )
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                str(ROOT / "scripts/verify_release_handoff.py"),
                str(self.assets),
                str(self.source),
                COMMIT,
                "--expected-tag",
                TAG,
            ],
            cwd=self.source,
            env={**os.environ, "GH_TOKEN": "synthetic-not-a-credential"},
            text=True,
            capture_output=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["tag"], TAG)
        self.assertFalse(marker.exists())

    def test_candidate_has_no_privileged_jobs_and_promoter_uses_main_approval(self):
        candidate = (ROOT / ".github/workflows/release-candidate.yml").read_text()
        for forbidden in ("contents: write", "id-token:", "attestations:"):
            self.assertNotIn(forbidden, candidate)
        self.assertIn("repository_dispatch:", candidate)
        self.assertNotIn("  push:", candidate)
        self.assertNotIn("workflow_dispatch:", candidate)
        self.assertIn("ref: ${{ github.workflow_sha }}", candidate)
        self.assertIn("github.event.client_payload.source_commit", candidate)
        promotion = (ROOT / ".github/workflows/release-promotion.yml").read_text()
        self.assertIn("workflow_run:", promotion)
        self.assertIn("github.workflow_sha", promotion)
        self.assertEqual(promotion.count("environment: release"), 2)
        self.assertIn(
            'merge-base --is-ancestor "$SOURCE_COMMIT" origin/main', promotion
        )
        publish = (ROOT / ".github/workflows/publish.yml").read_text()
        self.assertIn("workflow_dispatch:", publish)
        self.assertNotIn("types: [published]", publish)
        self.assertIn("if: github.ref == 'refs/heads/main'", publish)
        self.assertIn('--signer-digest "$PROMOTION_COMMIT"', publish)

    def test_candidate_selection_is_bounded_typed_data_not_authentication(self):
        self.assertEqual(
            handoff.read_selection(self.assets),
            {"source-tag": TAG, "source-commit": COMMIT},
        )
        with tempfile.TemporaryDirectory() as directory:
            assets = Path(directory)
            path = assets / "release-evidence.json"
            for value in (
                [],
                {"tag": TAG, "commit": "branch"},
                {"tag": TAG + "\nINJECTED=true", "commit": COMMIT},
            ):
                with self.subTest(value=value):
                    path.write_text(json.dumps(value))
                    with self.assertRaises(ValueError):
                        handoff.read_selection(assets)
            path.write_bytes(b" " * (128 * 1024 + 1))
            with self.assertRaisesRegex(ValueError, "bounded"):
                handoff.read_selection(assets)

    def test_bootstrap_isolation_excludes_selected_venv_and_pip_modules(self):
        marker = self.root / "synthetic-bootstrap-marker"
        selected = self.root / "selected"
        selected.mkdir()
        for name in ("venv", "pip"):
            (selected / (name + ".py")).write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('synthetic')\n"
            )
        env = {**os.environ, "GH_TOKEN": "synthetic-not-a-credential"}
        baseline = subprocess.run(
            [sys.executable, "-m", "venv", "--help"],
            cwd=selected,
            env=env,
            capture_output=True,
            timeout=15,
        )
        self.assertEqual(baseline.returncode, 0)
        self.assertTrue(marker.exists())
        marker.unlink()
        for module, option in (("venv", "--help"), ("pip", "--version")):
            isolated = subprocess.run(
                [sys.executable, "-I", "-m", module, option],
                cwd=selected,
                env=env,
                capture_output=True,
                timeout=15,
            )
            self.assertEqual(isolated.returncode, 0, isolated.stderr)
            self.assertFalse(marker.exists())
        for filename in (
            "release-candidate.yml",
            "release-promotion.yml",
            "publish.yml",
        ):
            text = (ROOT / ".github/workflows" / filename).read_text()
            self.assertNotIn("python -m venv", text)
            self.assertNotIn('/bin/python" -m pip', text)

    def test_failed_new_draft_deletes_only_returned_id(self):
        manifest = handoff.verify_handoff(self.assets, self.source, COMMIT)["manifest"]
        with (
            patch.object(draft, "gh") as gh,
            patch("scripts.verify_release_integrity.verify_tag"),
        ):
            # The helper loads an independent module; replace that explicit loader.
            integrity = handoff.load_trusted_helper("verify_release_integrity")
            integrity.verify_tag = lambda *args: None
            with patch.object(draft, "load_integrity", return_value=integrity):
                gh.side_effect = [
                    json.dumps({"id": 901, "tag_name": "v0.0.0", "draft": True}),
                    "",
                ]
                with self.assertRaisesRegex(ValueError, "identity"):
                    draft.create_draft(
                        self.assets,
                        self.source / "CHANGELOG.md",
                        "owner/repository",
                        TAG,
                        COMMIT,
                        manifest,
                    )
        self.assertEqual(
            gh.call_args_list[-1].args[0],
            ["api", "repos/owner/repository/releases/901", "--method", "DELETE"],
        )

    def test_successful_draft_uploads_only_known_id_and_verifies_final_bytes(self):
        manifest = handoff.verify_handoff(self.assets, self.source, COMMIT)["manifest"]
        integrity = handoff.load_trusted_helper("verify_release_integrity")
        integrity.verify_tag = lambda *args: None

        def response(arguments):
            if arguments[:2] == ["release", "download"]:
                destination = Path(arguments[arguments.index("--dir") + 1])
                for path in self.assets.iterdir():
                    shutil.copyfile(path, destination / path.name)
                return ""
            if arguments[1] == "repos/owner/repository/releases":
                return json.dumps({"id": 901, "tag_name": TAG, "draft": True})
            if arguments[1] == "repos/owner/repository/releases/901":
                return json.dumps(
                    {
                        "id": 901,
                        "tag_name": TAG,
                        "draft": True,
                        "prerelease": False,
                        "assets": [{"name": n} for n in manifest],
                    }
                )
            return "{}"

        with (
            patch.object(draft, "load_integrity", return_value=integrity),
            patch.object(draft, "gh", side_effect=response) as gh,
        ):
            result = draft.create_draft(
                self.assets,
                self.source / "CHANGELOG.md",
                "owner/repository",
                TAG,
                COMMIT,
                manifest,
            )
        self.assertEqual(result, 901)
        uploads = [
            c.args[0]
            for c in gh.call_args_list
            if c.args[0][1].startswith("https://uploads.github.com/")
        ]
        self.assertEqual(len(uploads), 5)
        self.assertTrue(
            all("/releases/901/assets?name=" in args[1] for args in uploads)
        )
        self.assertFalse(any("DELETE" in c.args[0] for c in gh.call_args_list))

    def test_failed_cleanup_requires_owner_review_without_deleting_other_id(self):
        manifest = handoff.verify_handoff(self.assets, self.source, COMMIT)["manifest"]
        integrity = handoff.load_trusted_helper("verify_release_integrity")
        integrity.verify_tag = lambda *args: None
        with (
            patch.object(draft, "load_integrity", return_value=integrity),
            patch.object(
                draft,
                "gh",
                side_effect=[
                    json.dumps({"id": 901, "tag_name": "v0.0.0", "draft": True}),
                    RuntimeError("synthetic delete failure"),
                ],
            ) as gh,
            self.assertRaisesRegex(RuntimeError, "owner review"),
        ):
            draft.create_draft(
                self.assets,
                self.source / "CHANGELOG.md",
                "owner/repository",
                TAG,
                COMMIT,
                manifest,
            )
        self.assertEqual(
            gh.call_args_list[-1].args[0],
            ["api", "repos/owner/repository/releases/901", "--method", "DELETE"],
        )

    def test_oversized_notes_refuse_before_any_release_write(self):
        manifest = handoff.verify_handoff(self.assets, self.source, COMMIT)["manifest"]
        integrity = handoff.load_trusted_helper("verify_release_integrity")
        integrity.verify_tag = lambda *args: None
        notes = self.root / "notes.md"
        notes.write_bytes(b"a" * (1024 * 1024 + 1))
        with (
            patch.object(draft, "load_integrity", return_value=integrity),
            patch.object(draft, "gh") as gh,
            self.assertRaisesRegex(ValueError, "bounded"),
        ):
            draft.create_draft(
                self.assets, notes, "owner/repository", TAG, COMMIT, manifest
            )
        gh.assert_not_called()


if __name__ == "__main__":
    unittest.main()
