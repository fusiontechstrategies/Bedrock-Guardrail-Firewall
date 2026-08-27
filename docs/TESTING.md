# Testing

## Verification philosophy

The test strategy separates deterministic local behavior from cloud integration behavior. Automated tests do not require AWS credentials and do not call a live AWS account.

This protects real workloads while still validating request construction, response parsing, failure handling, and control precedence through injected mocks.

## Completed local baseline

The published source history identifies a 4.0.0 baseline. Packaging and adoption work under `Unreleased` uses `4.1.0.dev0` to identify development toward the next minor version until a release version is separately approved. The table records point-in-time local validation and must be refreshed for any release candidate.

| Check | Result |
| --- | --- |
| Automated unit and integration tests | 177 passed with all optional integrations installed on Python 3.12 |
| Branch-aware line coverage | 86 percent |
| Built-in self-test | 7 of 7 passed |
| Built-in adversarial suite | 10 of 10 contained |
| Deterministic mutation suite | 100 rounds completed |
| Native Windows Python 3.12 | All 177 passed in the isolated pinned AWS and Presidio environment |
| Windows and Linux Python 3.10 through 3.14 | Configured as a required CI matrix; the unreleased branch must pass it before release |
| Missing Presidio model package check | Readiness failed before provider construction, download, socket creation, connection, or name resolution |
| Package validation | Wheel and source distribution built; metadata, isolated install, library import, console entry point, packaged policies, and default local state passed |
| Sanitized adoption fixture | 6 of 6 expected decisions and 4 of 4 high-risk containment cases passed with zero evaluation-time Python socket attempts and zero serialized high-risk values |
| Python compilation | Passed |
| Ruff formatting | Passed |
| Ruff linting | Passed |
| Bandit | No medium or high findings |
| AWS dependency audit | No advisories reported by `pip-audit` for the resolvable pinned set at validation time |
| Presidio dependency audit | No advisories reported for packages resolved by `pip-audit`; the direct model wheel is SHA-256 pinned but is outside the PyPI advisory lookup |
| Development dependency audit | No advisories reported by `pip-audit` for the resolvable pinned set at validation time |
| Distribution build dependency audit | No advisories reported by `pip-audit` for the resolvable pinned set at validation time |
| Secret scan | No credentials accepted after synthetic-fixture review |

Dependency results are point-in-time statements, not guarantees that a package has no vulnerability. Advisory data, package resolution, and audit coverage can change. Continuous scanning is configured accordingly.

## Automated coverage areas

### Configuration and policy

- Invalid runtime modes and regions
- Required remote services without required configuration
- Required signatures without live mode or a signing key
- Disallowed signing algorithms
- Missing, unknown, and duplicate JSON fields
- Unsupported schema versions
- Invalid threshold ordering
- Unsafe nested regex quantifiers
- Expected policy-digest mismatch

### Input validation

- Empty and non-string input
- NUL bytes
- Size limits
- Unsupported classifications
- Unsupported context fields
- Reserved bypass and profile fields
- Invalid request identifiers
- Invalid retrieval-context structure

### Privacy and local policy

- Email, Social Security number, card, IBAN, access-key pattern, and private-key detection
- Luhn and IBAN checksum rejection
- Irreversible redaction
- Denied topics
- Blocked and masked literal terms
- Prompt injection
- Zero-width obfuscation
- Exfiltration intent and destination risk
- Candidate-output evaluation

All credential-shaped values in tests are synthetic and are assembled to avoid publishing a usable credential.

### Authorization and capabilities

- Classification above clearance
- Role-based write restrictions
- Capability removal based on recommended action
- Content suppression for review, escalation, and block recommendations
- Monitor-mode separation of enforced and recommended action
- Trusted authorizer precedence in Lambda
- Rejection of body-supplied identity and classification trust
- Rejection of caller-selected profiles

### Grounding

- Unsupported output
- Retrieval-source qualifiers
- Query qualifier
- Guard-content qualifier
- Retrieval-context sanitization before optional AWS evaluation

### Amazon Bedrock Guardrails adapter

- `INPUT` and `OUTPUT` request construction
- `outputScope=FULL`
- No-intervention responses
- Blocking interventions
- Anonymized output
- Sensitive-information assessments
- Automated-reasoning findings
- Timeouts and failure actions
- Required guardrail disabled or not live
- No AWS client call in disabled mode
- No live AWS call after a local review, escalation, or block decision
- No output call after a Bedrock input block
- Explicit live authorization requirement
- Redacted request preview
- Installed botocore service-model contract for `ApplyGuardrail`
- Size validation and local re-evaluation of transformed cloud content

### Microsoft Presidio integration

- Pinned analyzer, spaCy, and English model installation
- NLP engine initialization through `doctor`
- Presidio-specific IP-address finding
- Irreversible redaction of a Presidio finding

### Audit and state

- Raw-content exclusion
- Raw-identity exclusion
- Stable HMAC pseudonyms
- Multiple-event hash-chain verification
- Tamper detection
- Missing, mismatched, and orphaned audit-chain head detection
- Request-identifier pseudonymization
- Local-audit failure handling
- Metadata-only incidents and metrics
- No local-path disclosure in the public response
- Signature status reporting

### Lambda and CLI

- Invalid event, JSON, base64, and body fields
- Duplicate JSON fields
- Security response headers
- Valid base64 requests
- CLI policy validation
- Opt-in action exit codes
- Live-mode confirmation gate
- Production readiness failure while offline
- Redacted AWS request preview

## Run the suite

```powershell
python -m unittest discover -s tests -v
python orchestrator.py --presidio-mode disabled self-test
python orchestrator.py --presidio-mode disabled red-team
python orchestrator.py --presidio-mode disabled chaos-test --rounds 100
```

Static and dependency checks:

```powershell
ruff format --check __init__.py orchestrator.py examples scripts tests
ruff check __init__.py orchestrator.py examples scripts tests
python scripts/check_public_markdown.py
bandit -c pyproject.toml -r orchestrator.py
pip-audit -r requirements-aws.txt
pip-audit -r requirements-presidio.txt
pip-audit -r requirements-dev.txt
pip-audit -r requirements-build.txt
gitleaks detect --no-git --source . --redact
python -m build
python -m twine check dist/*
```

Coverage:

```powershell
coverage run --branch --source=orchestrator -m unittest discover -s tests
coverage report --show-missing
```

## Continuous integration

GitHub Actions is configured to run:

- Unit tests on Windows and Linux
- Python 3.10, 3.11, 3.12, 3.13, and 3.14
- Pinned AWS SDK contract validation
- Pinned Presidio engine and redaction validation
- Wheel and source-distribution build plus isolated installed-CLI validation
- Deterministic sanitized adoption fixture
- Formatting and lint checks
- Static-security analysis
- Dependency vulnerability audits
- Secret scanning
- CodeQL analysis
- Pull-request dependency review

Workflows use minimal permissions and pin third-party actions to reviewed commit hashes.

## Safe cloud-integration validation

The automated suite injects fake Bedrock clients. A mock records the exact `apply_guardrail` arguments and returns controlled assessments. This validates the contract without using a real account.

The `aws-request-preview` command provides an additional no-network review path. It returns request structure, content lengths, abbreviated SHA-256 hashes, and qualifiers while omitting raw content.

## Release gate

A release candidate should not be tagged unless:

- All matrix tests pass.
- The built-in adversarial containment target is met.
- Formatting, lint, static-security, dependency, secret, and CodeQL checks pass.
- Policy validation passes and the digest is recorded.
- Documentation matches the runtime interface.
- The changelog and version are updated.
- No runtime state, credentials, private resource names, or generated evidence files are tracked.
