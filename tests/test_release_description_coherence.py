"""Keep the public package description aligned with the version being built."""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "bedrock-guardrail-firewall"
TOKEN_PUNCTUATION = "`*_[](){}<>,.:;!?\\\"'"


def _semantic_versions(text: str) -> set[str]:
    versions: set[str] = set()
    for token in text.split():
        candidate = token.strip(TOKEN_PUNCTUATION).removeprefix("v")
        parts = candidate.split(".")
        if len(parts) == 3 and all(part.isdigit() for part in parts):
            versions.add(candidate)
    return versions


def _current_release_versions(readme: str) -> set[str]:
    versions: set[str] = set()
    for line in readme.splitlines():
        words = {
            word.strip(TOKEN_PUNCTUATION).lower() for word in line.split()
        }
        if {"current", "release"} <= words:
            versions.update(_semantic_versions(line))
    return versions


def _pinned_install_versions(readme: str) -> set[str]:
    versions: set[str] = set()
    offset = 0
    while True:
        found = readme.find(PACKAGE_NAME, offset)
        if found < 0:
            return versions
        cursor = found + len(PACKAGE_NAME)
        if cursor < len(readme) and readme[cursor] == "[":
            closing = readme.find("]", cursor + 1)
            if closing < 0:
                offset = cursor
                continue
            cursor = closing + 1
        if readme.startswith("==", cursor):
            cursor += 2
            end = cursor
            while end < len(readme) and (
                readme[end].isdigit() or readme[end] == "."
            ):
                end += 1
            versions.update(_semantic_versions(readme[cursor:end]))
        offset = found + 1


class ReleaseDescriptionCoherenceTests(unittest.TestCase):
    @staticmethod
    def _source() -> tuple[str, str]:
        project = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )["project"]
        return project["version"], (ROOT / "README.md").read_text(encoding="utf-8")

    def test_readme_names_only_the_built_version_as_current(self) -> None:
        version, readme = self._source()
        self.assertEqual(
            _current_release_versions(readme),
            {version},
            "README.md must contain exactly one coherent current-release version",
        )
        self.assertEqual(
            _pinned_install_versions(readme),
            {version},
            "Every pinned package install must use only the build version",
        )

    def test_stale_first_use_pin_is_detected(self) -> None:
        version, readme = self._source()
        marker = f"{PACKAGE_NAME}=={version}"
        self.assertIn(marker, readme)
        stale = readme.replace(marker, f"{PACKAGE_NAME}==0.0.0", 1)
        self.assertNotEqual(_pinned_install_versions(stale), {version})


if __name__ == "__main__":
    unittest.main()
