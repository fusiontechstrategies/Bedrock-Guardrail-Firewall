import unittest

from scripts import check_release_tag_target as gate


class ReleaseTagTargetTests(unittest.TestCase):
    def setUp(self):
        self.sha = "a" * 40
        self.prefix = f"repos/{gate.REPOSITORY}"
        self.policy_path = (
            f"{self.prefix}/environments/release-tag/deployment-branch-policies"
            "?per_page=100"
        )
        self.context = {
            "RELEASE_TAG": "v4.1.2",
            "RELEASE_COMMIT": self.sha,
            "GITHUB_REPOSITORY": gate.REPOSITORY,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": gate.WORKFLOW_REF,
            "GITHUB_WORKFLOW_SHA": self.sha,
            "GITHUB_SHA": self.sha,
            "GITHUB_EVENT_NAME": "workflow_dispatch",
        }
        self.responses = {
            self.prefix: {"default_branch": "main"},
            f"{self.prefix}/branches/main": {
                "protected": True,
                "commit": {"sha": self.sha},
            },
            f"{self.prefix}/git/commits/{self.sha}": {
                "sha": self.sha,
                "verification": {"verified": True},
            },
            f"{self.prefix}/git/matching-refs/tags/v4.1.2": [],
            f"{self.prefix}/environments/release-tag": {
                "name": "release-tag",
                "can_admins_bypass": False,
                "deployment_branch_policy": {
                    "protected_branches": False,
                    "custom_branch_policies": True,
                },
                "protection_rules": [
                    {
                        "type": "required_reviewers",
                        "reviewers": [
                            {
                                "type": "User",
                                "reviewer": {"login": "fusiontechstrategies"},
                            }
                        ],
                    }
                ],
            },
            self.policy_path: {
                "total_count": 1,
                "branch_policies": [{"name": "main", "type": "branch"}],
            },
        }
        for workflow in gate.WORKFLOWS:
            self.responses[self.workflow_path(workflow)] = {
                "workflow_runs": [
                    {
                        "head_branch": "main",
                        "head_sha": self.sha,
                        "event": "push",
                        "status": "completed",
                        "conclusion": "success",
                    }
                ],
            }

    def workflow_path(self, workflow):
        return (
            f"{self.prefix}/actions/workflows/{workflow}/runs"
            f"?branch=main&event=push&head_sha={self.sha}&per_page=1"
        )

    def validate(self, version="4.1.2"):
        gate.validate_target(self.context, version, self.responses.__getitem__)

    def test_exact_signed_green_main_with_protected_environment_is_admitted(self):
        self.validate()

    def test_other_workflow_ref_is_refused(self):
        self.context["GITHUB_WORKFLOW_REF"] = self.context[
            "GITHUB_WORKFLOW_REF"
        ].replace("main", "draft")
        with self.assertRaisesRegex(gate.ReleaseTagError, "exact protected-main"):
            self.validate()

    def test_moved_main_is_refused(self):
        self.responses[f"{self.prefix}/branches/main"]["commit"]["sha"] = "b" * 40
        with self.assertRaisesRegex(gate.ReleaseTagError, "current protected main"):
            self.validate()

    def test_unsigned_commit_is_refused(self):
        self.responses[f"{self.prefix}/git/commits/{self.sha}"]["verification"][
            "verified"
        ] = False
        with self.assertRaisesRegex(gate.ReleaseTagError, "must be verified"):
            self.validate()

    def test_wrong_version_and_existing_tag_are_refused(self):
        with self.assertRaisesRegex(gate.ReleaseTagError, "package version"):
            self.validate(version="4.1.1")
        self.responses[f"{self.prefix}/git/matching-refs/tags/v4.1.2"] = [
            {"ref": "refs/tags/v4.1.2"}
        ]
        with self.assertRaisesRegex(gate.ReleaseTagError, "already exists"):
            self.validate()

    def test_admin_override_and_additional_tag_policy_are_refused(self):
        environment = self.responses[f"{self.prefix}/environments/release-tag"]
        environment["can_admins_bypass"] = True
        with self.assertRaisesRegex(gate.ReleaseTagError, "disallow admin overrides"):
            self.validate()
        environment["can_admins_bypass"] = False
        policies = self.responses[self.policy_path]
        policies["branch_policies"].append({"name": "main", "type": "tag"})
        policies["total_count"] = 2
        with self.assertRaisesRegex(gate.ReleaseTagError, "only the main branch"):
            self.validate()

    def test_failed_most_recent_ci_attempt_is_refused(self):
        self.responses[self.workflow_path("ci.yml")]["workflow_runs"][0][
            "conclusion"
        ] = "failure"
        with self.assertRaisesRegex(gate.ReleaseTagError, "ci.yml"):
            self.validate()
