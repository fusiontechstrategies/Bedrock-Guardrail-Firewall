"""Fail closed unless the release target is the reviewed protected main head."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

REPOSITORY = "fusiontechstrategies/Bedrock-Guardrail-Firewall"
WORKFLOW_REF = f"{REPOSITORY}/.github/workflows/release-tag.yml@refs/heads/main"
WORKFLOWS = ("ci.yml", "codeql.yml", "security.yml")
ROOT = Path(__file__).resolve().parents[1]


class ReleaseTagError(RuntimeError):
    """The requested release target did not pass admission."""


def require(condition, message):
    if not condition:
        raise ReleaseTagError(message)


def validate_target(environment, version, get):
    tag = environment["RELEASE_TAG"]
    commit = environment["RELEASE_COMMIT"]
    require(
        re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag), "Expected a stable version tag"
    )
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "Expected a full source commit SHA")
    require(
        environment["GITHUB_REPOSITORY"] == REPOSITORY
        and environment["GITHUB_REF"] == "refs/heads/main"
        and environment["GITHUB_WORKFLOW_REF"] == WORKFLOW_REF
        and environment["GITHUB_WORKFLOW_SHA"] == environment["GITHUB_SHA"] == commit
        and environment["GITHUB_EVENT_NAME"] == "workflow_dispatch",
        "The release must use the exact protected-main workflow and source revision",
    )
    require(tag == f"v{version}", "The tag does not match the reviewed package version")

    prefix = f"repos/{REPOSITORY}"
    repo = get(prefix)
    branch = get(f"{prefix}/branches/main")
    require(
        repo["default_branch"] == "main"
        and branch["protected"] is True
        and branch["commit"]["sha"] == commit,
        "The exact release commit must be the current protected main head",
    )
    record = get(f"{prefix}/git/commits/{commit}")
    require(
        record["sha"] == commit and record["verification"]["verified"] is True,
        "Release commit must be verified",
    )

    gate = get(f"{prefix}/environments/release-tag")
    rules = gate["protection_rules"]
    reviewers = [rule for rule in rules if rule["type"] == "required_reviewers"]
    require(
        gate["name"] == "release-tag"
        and gate["can_admins_bypass"] is False
        and gate["deployment_branch_policy"]
        == {"protected_branches": False, "custom_branch_policies": True}
        and len(reviewers) == 1
        and len(reviewers[0]["reviewers"]) == 1
        and reviewers[0]["reviewers"][0]["type"] == "User"
        and reviewers[0]["reviewers"][0]["reviewer"]["login"] == "fusiontechstrategies",
        "The tag environment needs owner review and must disallow admin overrides",
    )
    branch_policies = get(
        f"{prefix}/environments/release-tag/deployment-branch-policies?per_page=100"
    )
    require(
        branch_policies["total_count"] == 1
        and [
            (entry["name"], entry["type"])
            for entry in branch_policies["branch_policies"]
        ]
        == [("main", "branch")],
        "The tag environment must admit only the main branch",
    )

    for workflow in WORKFLOWS:
        result = get(
            f"{prefix}/actions/workflows/{workflow}/runs?branch=main&event=push&head_sha={commit}&per_page=1"
        )
        runs = result["workflow_runs"]
        require(
            bool(runs)
            and runs[0]["head_sha"] == commit
            and runs[0]["head_branch"] == "main"
            and runs[0]["event"] == "push"
            and runs[0]["status"] == "completed"
            and runs[0]["conclusion"] == "success",
            f"{workflow} has not passed on the exact main commit",
        )

    refs = get(f"{prefix}/git/matching-refs/tags/{tag}")
    require(
        not any(ref["ref"] == f"refs/tags/{tag}" for ref in refs),
        "The version tag already exists",
    )


def get_github_json(path):
    result = subprocess.run(
        ["gh", "api", "--method", "GET", path],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def main():
    try:
        version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
            "project"
        ]["version"]
        validate_target(os.environ, version, get_github_json)
    except (
        ReleaseTagError,
        KeyError,
        ValueError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"Release tag refused: {error}", file=sys.stderr)
        return 1
    print(
        "Verified release tag target",
        os.environ["RELEASE_TAG"],
        "at",
        os.environ["RELEASE_COMMIT"],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
