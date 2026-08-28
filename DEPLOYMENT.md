# Deployment Guide

## Purpose

This guide covers safe local use, optional Microsoft Presidio installation, authorized Amazon Bedrock Guardrails integration, and AWS Lambda deployment for version 4.1.0. Verify a distribution against an official release linked from this repository before deployment.

The runtime does not invoke a foundation model. It evaluates supplied input and optional candidate output, then returns a security decision and sanitized content.

## Deployment principles

1. Start in offline mode.
2. Validate the policy and run the complete local test suite.
3. Preview AWS request shapes before enabling live mode.
4. Use least-privilege IAM and explicit resource policies.
5. Keep raw content out of logs, queues, incident records, and metrics.
6. Require remote audit delivery for ephemeral production runtimes.
7. Pin the expected policy digest in production.
8. Roll out in monitor mode before enforcement when organizational policy permits.

## Supported runtime

- Core runtime on Python 3.10 through 3.14
- Pinned Presidio integration on Python 3.10 through 3.13
- Windows and Linux
- Standard-library-only core
- Optional `boto3` integration
- Optional Microsoft Presidio with spaCy

## Local installation

Create an isolated environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

The offline core requires no runtime package installation.

Validate it:

```powershell
python orchestrator.py --presidio-mode disabled doctor
python orchestrator.py policy-validate
python -m unittest discover -s tests -v
python orchestrator.py --presidio-mode disabled red-team
```

## Microsoft Presidio

Install the pinned Presidio stack:

```powershell
python -m pip install -r requirements-presidio.txt
python orchestrator.py --presidio-mode required doctor
```

Modes:

| Mode | Behavior |
| --- | --- |
| `disabled` | Uses deterministic local recognizers only |
| `auto` | Uses Presidio when available and retains deterministic recognizers |
| `required` | Applies the profile's failure action if Presidio is unavailable |

The production profile also requires Presidio, even if the runtime setting is accidentally changed to `disabled`.

## Runtime data

By default, runtime state is written to `.guardrail-data`:

```text
.guardrail-data/
  audit/events.ndjson
  audit/chain.json
  behavior.json
  incidents/
  locks/
  metrics.json
  privacy.key
  reviews/
```

The directory contains security metadata and key material. Do not commit, email, or publish it. Restrict access to the runtime identity and security operators.

Set another location with:

```powershell
$env:GUARDRAIL_DATA_DIR = "D:\GuardrailData"
```

On Linux:

```bash
export GUARDRAIL_DATA_DIR=/var/lib/bedrock-guardrail-firewall
```

## Stable privacy pseudonyms

The runtime uses HMAC-SHA256 for subject pseudonyms and content digests. A desktop deployment creates a random local key in the data directory.

For Lambda, containers, autoscaling groups, and other ephemeral or multi-instance deployments, inject the same secret key into every trusted instance:

```powershell
$key = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Fill($key)
$env:GUARDRAIL_PRIVACY_HMAC_KEY_B64 = [Convert]::ToBase64String($key)
```

Store the value in an approved secrets system. Do not put it in source code, deployment templates, shell history, or logs. Rotate it through a controlled process because rotation changes pseudonyms and digest continuity.

## Policy selection and integrity

The trusted operator selects the profile through a command option or environment variable:

```powershell
$env:GUARDRAIL_POLICY_PROFILE = "production"
```

Requests cannot select a profile.

Validate the policy bundle and capture its digest:

```powershell
python orchestrator.py policy-validate
```

Pin the approved digest:

```powershell
$env:GUARDRAIL_EXPECTED_POLICY_SHA256 = "approved-64-character-sha256"
```

Startup fails if either policy document changes without an approved digest update.

## AWS integration

Install the pinned SDK:

```powershell
python -m pip install -r requirements-aws.txt
```

Required settings for Bedrock Guardrails:

```powershell
$env:AWS_REGION = "us-gov-west-1"
$env:BEDROCK_GUARDRAIL_ID = "your-guardrail-id"
$env:BEDROCK_GUARDRAIL_VERSION = "1"
```

Always preview first:

```powershell
python orchestrator.py --aws-mode preview aws-request-preview `
  --input "Example request" `
  --candidate-output "Example response"
```

The CLI live gate requires both settings:

```powershell
python orchestrator.py `
  --aws-mode live `
  --enable-live-aws `
  evaluate `
  --input "Approved test content" `
  --no-record
```

`INPUT` and `OUTPUT` are evaluated independently. For output evaluation, retrieval documents use the `grounding_source` qualifier, the sanitized input uses `query`, and candidate output uses `guard_content`.

## Least-privilege IAM

Start with only the action required for Bedrock Guardrails and scope it to the approved guardrail resource. Adjust the partition for the target environment.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ApplyApprovedGuardrail",
      "Effect": "Allow",
      "Action": "bedrock:ApplyGuardrail",
      "Resource": "arn:aws-us-gov:bedrock:REGION:ACCOUNT_ID:guardrail/GUARDRAIL_ID"
    }
  ]
}
```

Do not add foundation-model invocation permissions unless another application component requires them.

Optional audit and review integrations need only their specific actions:

- `s3:PutObject` for the approved audit prefix
- `kms:Sign` for the approved asymmetric signing key
- `kms:GenerateDataKey` when the S3 KMS configuration requires it
- `sqs:SendMessage` for approved review queues

Use resource policies, VPC endpoints, service control policies, and permission boundaries where applicable.

## Remote audit controls

Optional settings:

```powershell
$env:GUARDRAIL_AUDIT_BUCKET = "approved-audit-bucket"
$env:GUARDRAIL_AUDIT_S3_KMS_KEY_ID = "approved-s3-kms-key"
$env:GUARDRAIL_AUDIT_SIGNING_KEY_ID = "approved-asymmetric-kms-key"
$env:GUARDRAIL_AUDIT_SIGNING_ALGORITHM = "RSASSA_PSS_SHA_256"
$env:GUARDRAIL_AUDIT_RETENTION_DAYS = "365"
$env:GUARDRAIL_AUDIT_OBJECT_LOCK = "true"
$env:GUARDRAIL_AUDIT_SIGNATURE_REQUIRED = "true"
$env:GUARDRAIL_REMOTE_AUDIT_REQUIRED = "true"
```

Important requirements:

- S3 Object Lock must be enabled for the bucket before object writes use retention settings.
- A KMS signing key must be asymmetric and support the configured SHA-256 signing algorithm.
- The runtime blocks when required remote delivery or required signing fails.
- Bucket name, object location, signing key identifier, and local paths are not included in the public response.

## Review queues

Configure up to three Amazon SQS queues:

```powershell
$env:GUARDRAIL_REVIEW_QUEUE_L1 = "approved-level-one-queue-url"
$env:GUARDRAIL_REVIEW_QUEUE_L2 = "approved-level-two-queue-url"
$env:GUARDRAIL_REVIEW_QUEUE_L3 = "approved-level-three-queue-url"
$env:GUARDRAIL_REMOTE_REVIEW_REQUIRED = "true"
```

Queue messages contain metadata only. Raw prompt text, candidate output, identities, secrets, and retrieval text are excluded.

## Lambda deployment

The source module exports `lambda_handler`. A portable source bundle uses the handler `orchestrator.lambda_handler`; an installed wheel uses `bedrock_guardrail_firewall.orchestrator.lambda_handler`.

Recommended configuration:

- Use a supported Python runtime.
- Package `orchestrator.py`, `guardrail_policy.json`, and `guardrail_policy_profiles.json` together.
- Alternatively, install the reviewed wheel into the deployment artifact; it carries both default policy documents as package data.
- Provide `boto3` in the deployment package when exact SDK behavior must be pinned.
- Put Presidio and its NLP model in a Lambda layer or container image if required.
- Set `GUARDRAIL_DATA_DIR` to `/tmp/guardrail-data`.
- Inject a stable `GUARDRAIL_PRIVACY_HMAC_KEY_B64` value.
- Require remote audit delivery because `/tmp` is ephemeral.
- Set reserved concurrency and API throttles appropriate to the workload.
- Use an authorizer to provide classification, role, clearance, tenant, and user identity.
- Disable payload logging in API Gateway and Lambda observability configurations.

The command-line and library defaults keep runtime state in `.guardrail-data` under the process working directory. Lambda deployments should always override that default with `GUARDRAIL_DATA_DIR=/tmp/guardrail-data` as described above.

Lambda treats deployment-time `GUARDRAIL_AWS_MODE=live` as operator authorization. Protect environment and deployment permissions accordingly.

The handler accepts only these body fields:

- `user_input`
- `candidate_output`
- `request_id`
- `user_context`

The caller can provide low-trust context such as requested capability, retrieval contexts, and source. Classification, role, clearance, tenant, and user identity come from authorizer context. Body-supplied values cannot override that boundary.

## Rollout sequence

1. Run local policy validation and all offline tests.
2. Deploy with AWS mode disabled.
3. Run `doctor` and inspect the reported security posture.
4. Use preview mode to approve request structure.
5. Configure IAM, networking, guardrail identifier, version, audit, and review resources.
6. Deploy in monitor mode to measure decisions without enforcing them.
7. Review false positives, false negatives, and policy thresholds.
8. Pin the approved policy digest.
9. Enable enforcement.
10. Verify audit-chain and remote-delivery monitoring.

## Operations

Health check:

```powershell
python orchestrator.py --profile production doctor
```

Audit integrity:

```powershell
python orchestrator.py verify-audit
```

Privacy-safe metrics:

```powershell
python orchestrator.py metrics-report
```

Adversarial regression test:

```powershell
python orchestrator.py --presidio-mode disabled red-team
```

## Incident response

If policy integrity, audit integrity, or credential exposure is suspected:

1. Disable live traffic or force the relevant caller path to fail closed.
2. Preserve local metadata and immutable remote audit objects.
3. Run `verify-audit` against a protected copy.
4. Rotate affected credentials and the privacy HMAC key if exposed.
5. Review IAM, deployment history, policy digests, and queue delivery records.
6. Do not paste raw sensitive prompts into public issue trackers.
7. Follow the private reporting process in `SECURITY.md` for product vulnerabilities.

## Decommissioning

1. Stop traffic and disable live mode.
2. Preserve records according to retention policy and legal requirements.
3. Remove review subscriptions and service integrations.
4. Revoke the runtime role and delete unneeded credentials.
5. Remove local runtime state through the organization's approved secure process.
6. Retain or destroy KMS keys only under an approved records-management decision.
