# Threat Model

## Scope

Bedrock Guardrail Firewall evaluates caller input, optional model output, retrieval context, and trusted authorization context. It produces a decision, sanitized content, restricted capabilities, and privacy-safe operational evidence.

This threat model covers the one-file Python runtime, policy documents, local state, optional Microsoft Presidio analysis, optional Amazon Bedrock Guardrails calls, optional Amazon S3 audit delivery, optional AWS KMS signing, optional Amazon SQS review routing, the CLI, and the Lambda entry point.

## Security objectives

1. Prevent sensitive data from reaching downstream systems when a configured detector identifies it.
2. Prevent untrusted callers from weakening policy or selecting a relaxed profile.
3. Fail safely when a required control is unavailable.
4. Prevent raw prompt, output, retrieval, and identity data from entering operational records.
5. Make local audit modification detectable.
6. Avoid accidental AWS network calls during local development and tests.
7. Restrict downstream capabilities based on the strongest recommended action.
8. Bound resource use from hostile or malformed input.

## Assets

- User input and candidate output
- Retrieval context
- Identity, tenant, role, and clearance context
- Guardrail and policy configuration
- Privacy HMAC key
- AWS credentials available to the runtime
- Local and remote audit evidence
- Review and incident metadata
- Runtime availability and decision integrity

## Trust boundaries

| Boundary | Trusted side | Untrusted or lower-trust side |
| --- | --- | --- |
| CLI configuration | Operator-selected arguments and environment | Evaluated content and caller context |
| Lambda authorization | Lambda authorizer context | Request body and headers |
| Policy loading | Approved local files and pinned digest | Modified, malformed, or oversized JSON |
| Optional cloud integration | Approved AWS account, region, guardrail, keys, bucket, and queues | Network failures and unexpected service responses |
| Local evidence | Restricted runtime directory | Other local users and post-write tampering |
| Downstream capabilities | Trusted application enforcement | Caller attempts to request elevated operations |

## Primary threats and mitigations

### Prompt injection and instruction manipulation

Threats include attempts to ignore policy, reveal hidden prompts, impersonate trusted roles, use invisible characters, or request a bypass.

Mitigations:

- Unicode normalization and zero-width character removal for detection
- Configurable prompt-attack patterns
- Role-token heuristics
- Strongest-action decision precedence
- No request field that enables bypass or selects enforcement mode
- Capability shutdown for review, escalation, and block decisions

Residual risk: language-based attacks can be novel, indirect, multilingual, or highly contextual. Add policy patterns, Presidio recognizers, and Bedrock Guardrails configurations that match the deployment.

### Sensitive data disclosure

Threats include PII, credentials, keys, tokens, private-key material, controlled markings, and sensitive text in retrieval context or output.

Mitigations:

- Deterministic recognizers for common identifiers and secrets
- Luhn validation for card numbers
- IBAN checksum validation
- Optional Presidio detection
- Non-reversible replacement tokens
- Privacy processing before optional cloud evaluation
- Input, output, and retrieval-context inspection
- Metadata-only audit, review, incident, behavior, and metrics stores

Residual risk: no detector can identify every sensitive value. Organization-specific identifiers should be added through policy or code review.

### Policy weakening and confused-deputy attacks

Threats include caller-selected profiles, caller-selected enforcement mode, forged roles, forged clearance, or unsupported context fields.

Mitigations:

- Strict allowlist for context fields
- Explicit reserved-field rejection
- Trusted profile selection at startup
- Lambda authorizer values override body values
- Role and clearance checks
- Unknown JSON fields and duplicate keys are rejected
- Optional exact policy-digest pinning

Residual risk: a compromised deployment operator or authorizer can still supply trusted configuration. Protect those control planes separately.

### Cloud-call accidents and data egress

Threats include unintended AWS calls from developer machines, tests, or preview workflows.

Mitigations:

- AWS mode defaults to `disabled`
- No AWS client creation in disabled or preview mode
- CLI live mode requires `--enable-live-aws`
- Request preview redacts all content and performs no network operation
- Automated tests use injected mocks
- No foundation-model invocation code

Residual risk: a trusted operator can deliberately enable live mode. Deployment permissions and change controls must protect configuration.

### External-service failure and malformed responses

Threats include timeouts, unavailable services, unexpected assessment objects, omitted intervention explanations, or failed remote evidence delivery.

Mitigations:

- Bounded SDK timeouts and retries
- Profile-defined external failure action
- Production profile fails closed
- Unexplained Bedrock intervention blocks
- Required audit signing, remote audit, and remote review failures block
- Safe error types without exception details

Residual risk: optional integrations in the balanced profile can degrade without blocking. Use the production profile where those controls are mandatory.

### Audit tampering and repudiation

Threats include local event editing, deletion, truncation, or reordering.

Mitigations:

- Canonical JSON serialization
- SHA-256 hash chain
- Cross-process file locking
- Atomic chain-head updates
- Local integrity verification command
- Optional KMS signatures
- Optional S3 Object Lock compliance retention
- Optional S3 KMS encryption

Residual risk: local deletion of the complete chain is not independently detectable without remote monitoring. Production deployments should require remote audit delivery and alert on gaps.

### Resource exhaustion

Threats include oversized input, deeply nested JSON, excessive retrieval items, large audit records, unbounded behavior data, and lock contention.

Mitigations:

- Input, output, context, policy, and audit-size limits
- JSON nesting limit
- Retrieval-item count limit
- Behavior retention and maximum-subject bounds
- Lock timeout
- Controlled regex feature validation for policy expressions
- Bounded AWS timeouts and retries

Residual risk: high request volume still needs rate limits, concurrency controls, quotas, and capacity planning outside this runtime.

### Regex denial of service

Threats include malicious policy expressions with nested quantifiers, recursion, backreferences, or lookbehind complexity.

Mitigations:

- Pattern length bounds
- Nested-quantifier rejection
- Rejection of backreferences, recursion, and selected lookbehind constructs
- Policy files are trusted deployment artifacts

Residual risk: static regex screening is conservative, not a mathematical proof of linear execution. Review custom expressions and keep input limits enabled.

### Unauthorized downstream actions

Threats include use of a sanitized or risky request to trigger writes or external calls.

Mitigations:

- Capability map returned with each decision
- Role allowlists for retrieval, write, and external API use
- Write and external API disabled after sanitization
- All capabilities disabled for review, escalation, or block recommendations
- Monitor mode still restricts capabilities according to the recommendation

Residual risk: the calling application must actually enforce the returned action and capabilities.

## Data-flow guarantees

- Raw content is used in memory for evaluation.
- Local privacy controls run before optional Bedrock Guardrails calls.
- Local review, escalation, or block decisions short-circuit live AWS evaluation.
- Sanitized input is sent for `INPUT` evaluation.
- Sanitized retrieval context, sanitized query, and sanitized candidate output are sent for `OUTPUT` evaluation.
- Bedrock-transformed text is size-checked and re-evaluated locally before release.
- Raw content is not placed in audit, behavior, metrics, review, or incident records.
- Public results do not expose local paths, queue URLs, bucket names, key identifiers, or exception messages.
- Content fields are released only for allow and sanitize recommendations.
- Request identifiers are HMAC-pseudonymized before audit, review, and incident storage.

## Assumptions

- The host, interpreter, policy files, and deployment identity are trusted.
- The caller enforces the returned action and capability restrictions.
- IAM, network, encryption, logging, and retention controls are correctly configured.
- Authorizer context, including classification and identity, is produced by an authenticated and authorized component.
- Operators protect environment variables and the data directory.

## Out of scope

- Foundation-model inference quality
- Complete semantic truth verification
- Model-provider security
- Host compromise after an attacker obtains administrator privileges
- Key recovery after a privacy HMAC key is lost
- Automatic creation of AWS resources
- Organization-specific legal or records-management determinations

## Security review checklist

- [ ] Policy and profile files were reviewed and the digest was pinned.
- [ ] The production profile is used where Presidio and Bedrock are mandatory.
- [ ] Live AWS mode was explicitly approved.
- [ ] IAM resources are narrowly scoped.
- [ ] Runtime and API payload logging are disabled or safely filtered.
- [ ] A stable privacy HMAC key is injected securely.
- [ ] Remote audit delivery and alerting are enabled for ephemeral runtimes.
- [ ] Review queues contain metadata only.
- [ ] The calling application enforces action and capability results.
- [ ] Rate limits and concurrency limits are configured.
- [ ] The full automated suite, red-team suite, and audit verification pass.
