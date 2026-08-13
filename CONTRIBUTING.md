# Contributing

Thank you for helping improve Bedrock Guardrail Firewall.

## Before you start

- Search existing issues and pull requests.
- Use a public issue for non-sensitive bugs and feature proposals.
- Follow `SECURITY.md` for vulnerabilities or sensitive findings.
- Use only synthetic data in examples and tests.
- Keep the production runtime in `orchestrator.py`.
- Do not add implicit AWS calls or foundation-model invocation.
- Do not weaken fail-safe production behavior.

## Development setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

Optional integration packages:

```powershell
python -m pip install -r requirements-aws.txt
python -m pip install -r requirements-presidio.txt
```

## Required checks

```powershell
ruff format --check orchestrator.py tests
ruff check orchestrator.py tests
python -m unittest discover -s tests -v
python orchestrator.py --presidio-mode disabled self-test
python orchestrator.py --presidio-mode disabled red-team
bandit -c pyproject.toml -r orchestrator.py
pip-audit -r requirements-aws.txt
pip-audit -r requirements-presidio.txt
pip-audit -r requirements-dev.txt
```

No test or pull request should require live AWS credentials. Use injected clients and synthetic responses for AWS integration behavior.

## Pull requests

A focused pull request should:

- Explain the problem and security impact.
- Include tests for new behavior and regressions.
- Update policy documentation when the schema changes.
- Update deployment documentation when configuration changes.
- Update `CHANGELOG.md` for user-visible changes.
- Preserve Python 3.10 compatibility.
- Avoid credentials, private resource names, raw operational records, and personal data.
- Keep third-party actions pinned to a reviewed commit hash.

## Policy changes

Policy changes can materially affect blocking, redaction, and review decisions. Include:

- The reason for the new or changed control
- Positive fixtures that should trigger
- Negative fixtures that must not trigger
- Regex-complexity review when applicable
- The new policy digest from `policy-validate`

## Coding guidelines

- Prefer standard-library features for the core runtime.
- Keep optional imports safe when dependencies are absent.
- Validate data at trust boundaries.
- Return safe error categories instead of exception messages.
- Use atomic writes and cross-process locks for shared state.
- Avoid raw-content logging.
- Use the strongest-action-wins rule for control aggregation.
- Add concise comments only where the security reasoning is not obvious.

## Commit and review hygiene

- Write clear, imperative commit subjects.
- Keep unrelated changes separate.
- Resolve all continuous-integration findings.
- Expect security-sensitive changes to receive additional review.

By contributing, you agree that your contribution is licensed under the Apache License 2.0.
