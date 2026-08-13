# Support

## Questions and configuration help

Use GitHub Discussions when available for:

- Installation questions
- Policy-tuning ideas
- Deployment architecture
- Presidio configuration
- Safe Bedrock Guardrails integration
- Feature design

Use a GitHub issue for a reproducible non-sensitive defect.

## Before requesting help

Run these safe local commands:

```powershell
python orchestrator.py --presidio-mode disabled doctor
python orchestrator.py policy-validate
python orchestrator.py --presidio-mode disabled self-test
python --version
```

Include the resulting product version, Python version, operating system, selected modes, and sanitized error category.

## Protect sensitive information

Never post:

- AWS credentials or session tokens
- Guardrail identifiers from a private environment
- Account identifiers, queue URLs, bucket names, or KMS key identifiers
- Real prompt or response content
- Personal data
- Classified data or controlled unclassified information
- Audit, review, or incident files from production

Replace sensitive values with obvious placeholders.

## Security reports

Use the private process in `SECURITY.md`. Do not report vulnerabilities through public issues or discussions.

## Support expectations

This is a community-maintained open-source project. Support is provided on a best-effort basis and does not include an availability, response-time, or remediation guarantee.
