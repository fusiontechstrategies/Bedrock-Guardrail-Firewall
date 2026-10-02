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
- Runtime input and state are bounded. CLI files must be regular files; stdin is capped at 1 MiB with a ten-second stream completion deadline.
- Audit event records receive owner-only protection before their first byte is written. Existing unsafe event-file ownership, links, or broad permissions fail closed. On Windows, protect the audit directory with an owner-only ACL as a deployment step; the chain summary uses the directory permissions and contains no request content, only schema metadata, the last hash, and a timestamp.
- Release verification runs trusted default-branch tools and reauthenticates distribution provenance immediately before publication.
- Release tools use a hashed dependency closure and non-isolated builds to prevent index resolution during packaging.
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

Compact JWT/JOSE detection decodes a bounded protected header rather than relying
on its textual base64url prefix. It recognizes credentials for containment and
does not verify their signatures, authorize their holders, or validate claims.
Encoded header, payload, and signature segments are limited to 4,096, 32,768,
and 8,192 characters respectively. Oversized compact candidates raise a local
validation error instead of silently bypassing privacy processing.
Header suffix checks for hyphen or underscore labels are limited to 64 candidates;
exhaustion fails closed.

Opaque credentials are recognized after case-insensitive `access_token` and
`refresh_token` labels with `=` or `:` separators (including quoted values), and
after the `Bearer` scheme. Values use ASCII letters, digits, `.`, `_`, `~`, `+`,
`/`, `=`, and `-`; whitespace, quotes, query `&`, and common field punctuation end
a value. Each opaque value is limited to 4,096 characters, with at most 64 labelled
candidates per text field. Oversized values, candidate exhaustion, and unsupported
characters inside a candidate fail local validation before cloud evaluation.
The existing Unicode normalization applies before recognition. Compact JOSE
credentials retain their separate segment limits and policy. The exact obvious
placeholders `token`, `your_token`, `your-token`, `example-token`, `placeholder`,
and `redacted` are excluded, case-insensitively. Unlabelled arbitrary strings and
encoded or split credential formats outside this grammar are not a detection
guarantee. Recognition contains text; it does not authenticate a credential.

Bare `Bearer` values must be at least 16 characters, so ordinary phrases such as
`bearer bonds`, `bearer shares`, and `bearer plant` remain unchanged. Explicit
`Authorization: Bearer` headers (including quoted JSON headers), `access_token`,
and `refresh_token` fields contain shorter values too. Short bare Bearer values
are outside the supported grammar; this threshold is not an entropy test.
Excluded placeholders and short bare prose do not consume the credential-candidate
budget. The existing text-size limits still bound their linear scan.

Lambda cold startup requires `GUARDRAIL_REMOTE_AUDIT_REQUIRED=true`, a remote
audit bucket, live AWS mode, and an injected stable privacy HMAC key. Request data
cannot select a local-only audit profile. Failed required delivery blocks content
release; this control does not prove that a deployment's S3 retention or IAM policy
was configured correctly.
The startup requirement is checked before malformed-event admission. Malformed
payloads rejected before request processing do not create audit event records.

Release verification parses full PEP 508 requirements and compares complete
canonical optional markers with reviewed `pyproject.toml` metadata and exact pins.
Trusted publication verification installs hashed parser pins from the trusted
default-branch checkout into a fresh virtual environment and runs in isolated mode.
Only the supported extra equality and reviewed Python-version conjunction are
admitted; broadened/disjunctive/duplicate predicates are refused. Archive paths
containing `~` followed by an ASCII digit are conservatively refused in wheels,
source distributions, and source normalization to exclude Windows short-name
aliases, independently of host filesystem settings.

Policy identifiers must be unique after the exact normalization used by runtime
maps. Whitespace collisions are rejected in topic, role, weight, and profile
names; entity-action names additionally reject uppercase collisions. Accepted
documents retain their existing digest format and are independent of JSON
object member order.

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
