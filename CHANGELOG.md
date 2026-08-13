# Changelog

All notable changes to this project are documented here.

The format follows Keep a Changelog, and versions follow semantic versioning.

## [Unreleased]

### Planned

- Community feedback and additional synthetic red-team cases

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

[Unreleased]: https://github.com/fusiontechstrategies/bedrock-guardrail-firewall/compare/v4.0.0...HEAD
[4.0.0]: https://github.com/fusiontechstrategies/bedrock-guardrail-firewall/releases/tag/v4.0.0
