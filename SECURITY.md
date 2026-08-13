# Security Policy

## Supported versions

| Version | Security updates |
| --- | --- |
| 4.x | Supported |
| Earlier versions | Not supported |

Use the latest release and pinned dependency files.

## Report a vulnerability privately

Do not open a public issue for a suspected vulnerability, exposed credential, private resource name, or sensitive operational record.

Use GitHub Private Vulnerability Reporting:

1. Open the repository's **Security** tab.
2. Select **Advisories**.
3. Select **Report a vulnerability**.

Include:

- A clear description and affected version
- Reproduction steps or a minimal proof of concept
- Expected and observed behavior
- Security impact
- Suggested remediation, if available
- Whether the issue is already public

Do not include real credentials, personal data, classified data, controlled unclassified information, proprietary prompts, or live AWS resource names. Use synthetic fixtures.

## Response process

Maintainers will attempt to acknowledge a complete report within three business days. Validation, remediation, release, and disclosure timing depend on severity and complexity. Reporters will be credited when requested and appropriate.

## Security design

The project follows these defaults:

- AWS calls are disabled unless explicitly enabled.
- Preview mode performs no network operation.
- Requests cannot select policy profiles or enforcement mode.
- Privacy filtering runs before optional cloud evaluation.
- Production requirements fail closed.
- Audit and review records contain metadata, not raw content.
- Public responses exclude local paths and remote resource names.
- Local audit records form a hash chain.
- Runtime input and state are bounded.
- Optional dependencies are pinned and continuously audited.

See [Threat Model](docs/THREAT_MODEL.md) for trust boundaries, assumptions, residual risk, and deployment responsibilities.

## Deployment security

Before enabling live AWS mode:

- Review the exact policy digest.
- Use least-privilege IAM.
- Protect authorizer and deployment configuration.
- Disable unsafe payload logging.
- Inject a stable privacy HMAC key through an approved secret channel.
- Require remote audit delivery for ephemeral runtimes.
- Monitor missing audit events and review-queue delivery failures.
- Verify that the caller enforces returned actions and capabilities.

## Scope

Security reports may include:

- Bypass of trusted profile or authorization boundaries
- Raw-content disclosure in audit or response data
- Accidental AWS calls in disabled or preview mode
- Fail-open behavior in required production controls
- Audit-chain integrity failures
- Unsafe policy parsing or regular-expression behavior
- Credential or private-key detection bypasses
- Injection or deserialization vulnerabilities
- Dependency vulnerabilities with a practical impact

General support questions and policy-tuning requests belong in GitHub Discussions or a normal issue without sensitive data.
