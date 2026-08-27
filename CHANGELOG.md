# Changelog

All notable changes to this project are documented here.

The format follows Keep a Changelog, and versions follow semantic versioning.

## [Unreleased]

### Added

- Conventional wheel and source-distribution metadata with a typed public library interface
- `bedrock-guardrail-firewall` console entry point
- Pinned `aws` and `presidio` optional dependency groups
- Exact botocore service-model pin and SHA-256 verification for the Presidio English model wheel
- Offline six-case sanitized demo with measurable decision and containment results
- Continuous-integration package build, metadata, clean-install, import, resource, and CLI checks
- Scheduled Semgrep and Trivy scans with native GitHub code-scanning uploads and retained SARIF evidence

### Changed

- Installed execution resolves explicit relative paths from the working directory while direct one-file execution preserves source-relative behavior
- Installed packages retain their bundled default policy documents while runtime state remains outside the package directory
- Distribution metadata uses `4.1.0.dev0` to identify development toward the next minor version without presenting it as a release
- Quick start now covers a clean Windows, Linux, or macOS source installation
- GitHub workflows avoid retaining checkout credentials and Dependabot updates use explicit cooldowns

### Security

- Serialized shared Presidio initialization so concurrent requests wait for a complete analyzer or receive the same fail-closed initialization error
- Added defensive degraded-state handling when a required Presidio analyzer is unexpectedly unavailable
- Expanded sanitized-demo evaluation containment across Python socket creation, connection, and name-resolution entry points
- Redacted AWS request previews use a non-HTML marker while continuing to expose only length and digest metadata

## [4.0.0] - 2026-08-12

### Added

- Standard-library-only offline core
- Explicit `disabled`, `preview`, and `live` AWS modes
- Two-part CLI authorization gate for live AWS calls
- Current Amazon Bedrock `ApplyGuardrail` adapter for input and output
- Grounding-source, query, and guard-content qualifiers
- Redacted AWS request preview
- Optional Microsoft Presidio integration with deterministic fallback recognizers
- PII, credential, token, private-key, and controlled-marking detection
- Luhn and IBAN checksum validation
- Input, output, and retrieval-context sanitization
- Local short-circuiting that prevents live cloud transmission after review, escalation, or block decisions
- Local re-evaluation and size validation of transformed cloud content
- Prompt-injection and zero-width obfuscation detection
- Denied-topic, blocked-term, masked-term, and exfiltration controls
- Role, capability, classification, and clearance enforcement
- Lexical grounding and citation checks
- Trusted policy profiles and exact policy-digest pinning
- Strongest-action decision precedence and risk floors
- Monitor and enforce modes
- Capability restrictions based on recommended action
- Metadata-only audit, review, incident, behavior, and metrics records
- HMAC-SHA256 subject pseudonyms and content digests
- Secure privacy-key injection for ephemeral and multi-instance deployments
- Cross-platform advisory file locks and atomic state writes
- SHA-256 audit hash chain and integrity verification
- Optional KMS audit signatures
- Optional S3 Object Lock audit delivery with KMS encryption
- Optional tiered SQS review routing
- Bounded behavior retention and request sizes
- Lambda handler with strict request parsing and authorizer trust boundary
- Doctor, policy validation, self-test, red-team, chaos, metrics, and audit commands
- Opt-in action-specific CLI exit codes
- 163-test core and optional-integration suite, 85 percent branch-aware coverage, and cross-platform continuous integration
- Threat model, policy schema, deployment guide, quick reference, and project governance

### Changed

- Replaced reversible encryption with non-reversible redaction
- Replaced legacy model-centric behavior with a model-independent guardrail firewall
- Replaced outdated dependency ranges with isolated pinned dependency groups
- Replaced the legacy deployment document with maintained Markdown documentation

### Security

- Removed implicit AWS client creation
- Removed fail-open production paths
- Removed untrusted request control over policy profiles
- Removed raw content from operational evidence
- Added duplicate-key and unknown-field rejection
- Added safe regex validation and strict JSON bounds
- Added public-response filtering for local and cloud resource details
- Added blocked-content suppression and request-identifier pseudonymization in stored evidence

[Unreleased]: https://github.com/fusiontechstrategies/Bedrock-Guardrail-Firewall/compare/e19e426522a4b9975cc9e37b8b9b68e91dd7344b...HEAD
[4.0.0]: https://github.com/fusiontechstrategies/Bedrock-Guardrail-Firewall/commit/e19e426522a4b9975cc9e37b8b9b68e91dd7344b
