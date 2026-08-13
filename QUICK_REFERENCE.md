# Quick Reference

## Safe local checks

```powershell
python orchestrator.py --presidio-mode disabled doctor
python orchestrator.py policy-validate
python orchestrator.py --presidio-mode disabled self-test
python orchestrator.py --presidio-mode disabled red-team
python orchestrator.py --presidio-mode disabled chaos-test --rounds 100
```

These commands do not call AWS when AWS mode is `disabled`, which is the default.

## Evaluate content

```powershell
python orchestrator.py --presidio-mode disabled evaluate `
  --input "Summarize the approved release checklist." `
  --no-record
```

Evaluate input and candidate output together:

```powershell
python orchestrator.py --presidio-mode disabled evaluate `
  --input "Summarize the source." `
  --candidate-output "The proposed response." `
  --context-json '{"retrieval_contexts":[{"id":"source1","text":"Approved source material."}]}' `
  --no-record
```

Use files for larger content:

```powershell
python orchestrator.py evaluate `
  --input-file .\input.txt `
  --candidate-output-file .\output.txt `
  --context-file .\context.json
```

## Exit codes

Default CLI evaluation exits with `0` when the command completes, regardless of the policy action. Add `--action-exit-codes` for pipeline enforcement.

| Code | Meaning |
| ---: | --- |
| `0` | Allowed or command completed |
| `2` | Configuration, validation, or runtime error |
| `10` | Sanitized |
| `20` | Review or escalation required |
| `30` | Blocked |
| `130` | Interrupted safely |

## AWS request preview

```powershell
python orchestrator.py --aws-mode preview aws-request-preview `
  --input "Preview this request" `
  --candidate-output "Preview this response"
```

The preview contains lengths, hashes, qualifiers, and request structure. It omits raw content and performs no network operation.

## Authorized live AWS evaluation

```powershell
$env:AWS_REGION = "us-gov-west-1"
$env:BEDROCK_GUARDRAIL_ID = "your-guardrail-id"
$env:BEDROCK_GUARDRAIL_VERSION = "1"

python orchestrator.py `
  --aws-mode live `
  --enable-live-aws `
  evaluate `
  --input "Evaluate this request" `
  --no-record
```

Do not use live mode until the account, region, IAM policy, guardrail version, logging controls, and data-handling approvals have been reviewed.

## Profiles

```powershell
python orchestrator.py --profile balanced doctor
python orchestrator.py --profile production doctor
```

`production` reports not ready unless required Presidio and AWS controls are active.

## Audit and metrics

```powershell
python orchestrator.py verify-audit
python orchestrator.py metrics-report
```

Runtime state defaults to `.guardrail-data`. Override it with `--data-dir` or `GUARDRAIL_DATA_DIR`.

## Policy integrity

```powershell
python orchestrator.py policy-validate
```

Copy the reported digest into `GUARDRAIL_EXPECTED_POLICY_SHA256` to require that exact policy bundle at startup.

## Lambda request shape

```json
{
  "user_input": "Summarize the approved source.",
  "candidate_output": "Optional candidate response.",
  "request_id": "request-123",
  "user_context": {
    "requested_capability": "retrieval",
    "retrieval_contexts": [
      {
        "id": "source1",
        "text": "Approved source material."
      }
    ]
  }
}
```

Trusted values such as `classification`, `role`, `clearance_level`, `tenant_id`, and `user_id` should come from the Lambda authorizer context. Body-supplied identity, authorization, classification, profile, and enforcement values are ignored or rejected.
