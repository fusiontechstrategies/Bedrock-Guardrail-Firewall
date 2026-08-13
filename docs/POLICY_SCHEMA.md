# Policy Schema

## Overview

Bedrock Guardrail Firewall loads two strict JSON documents:

- `guardrail_policy.json` defines controls, roles, weights, grounding rules, and limits.
- `guardrail_policy_profiles.json` defines trusted enforcement profiles.

Both documents use schema version `2`. Unknown fields, missing required fields, duplicate JSON keys, excessive nesting, invalid values, and unsafe regular-expression features are rejected.

## Policy document

Top-level fields:

| Field | Type | Purpose |
| --- | --- | --- |
| `schema_version` | Integer | Must equal `2` |
| `policy_id` | String | Stable policy identifier |
| `policy_version` | String | Human-managed policy release |
| `denied_topics` | Object | Named groups of blocking regular expressions |
| `blocked_terms` | String array | Literal terms that block |
| `masked_terms` | String array | Literal terms replaced before downstream use |
| `prompt_attack_patterns` | String array | Regular expressions for instruction manipulation |
| `presidio_entities` | String array | Entity names requested from Presidio |
| `entity_actions` | Object | Entity name to action mapping |
| `capability_roles` | Object | Capability name to trusted-role allowlist |
| `risk_weights` | Object | Detector name to numeric contribution |
| `grounding` | Object | Local grounding and citation rules |
| `limits` | Object | Policy-level request bounds |

Identifiers accept letters, numbers, periods, underscores, and hyphens. They must start with a letter or number and contain at most 128 characters.

## Actions

The following action values are accepted:

| Value | Precedence | Effect |
| --- | ---: | --- |
| `allow` | 0 | Continue |
| `sanitize` | 1 | Continue only with redacted content and restricted capabilities |
| `queue_for_review` | 2 | Hold for human review |
| `escalate` | 3 | Hold for urgent review |
| `block` | 4 | Stop processing |

When controls disagree, the action with the highest precedence wins.

## Denied topics

`denied_topics` maps a descriptive name to one or more regular expressions.

```json
{
  "denied_topics": {
    "example_policy_category": [
      "\\bprohibited\\b.{0,40}\\brequest\\b"
    ]
  }
}
```

A match blocks the request. Patterns are compiled case-insensitively with dot matching newlines.

Policy loading rejects patterns longer than 512 characters and selected constructs associated with unsafe complexity, including nested quantifiers, backreferences, recursion, and complex lookbehind.

## Literal terms

`blocked_terms` and `masked_terms` are literal strings, not regular expressions.

```json
{
  "blocked_terms": ["prohibited phrase"],
  "masked_terms": ["internal reference"]
}
```

Literal matching is case-insensitive and respects word boundaries when the term starts or ends with an alphanumeric character.

## Privacy entities

`presidio_entities` controls the entity list requested from Microsoft Presidio. Deterministic recognizers remain enabled independently.

`entity_actions` maps uppercase entity names to actions:

```json
{
  "entity_actions": {
    "EMAIL_ADDRESS": "sanitize",
    "PRIVATE_KEY": "block"
  }
}
```

An entity without an explicit mapping defaults to `sanitize`.

Built-in deterministic recognizers include:

- US Social Security numbers
- Payment-card candidates with Luhn validation
- IBAN candidates with checksum validation
- Email addresses
- North American phone numbers
- AWS access-key patterns
- AWS secret-access-key assignments
- GitHub, Slack, and OpenAI token patterns
- Private-key headers
- JSON Web Tokens
- Common controlled-information markings

The deterministic Social Security number recognizer reports the internal label `US_SOCIAL_SECURITY_NUMBER`. Presidio reports its corresponding entity as `US_SSN`. The default policy maps both labels to `block`.

## Capability roles

`capability_roles` maps a capability to the roles allowed to request it.

```json
{
  "capability_roles": {
    "retrieval": ["analyst", "user"],
    "write": ["security_engineer"],
    "external_api": ["security_engineer"]
  }
}
```

Role and capability selection must come from trusted application boundaries. The Lambda handler obtains role from authorizer context and does not trust a body-supplied role.

## Risk weights

Risk weights are numbers from `0.0` through `1.0`.

Known detector names include:

- `authorization`
- `aws_bedrock_guardrail`
- `behavior`
- `denied_topic`
- `exfiltration`
- `local_grounding_heuristic`
- `privacy`
- `prompt_attack`
- `system`
- `term_filter`

`default` applies to an unlisted detector.

The final risk score includes action-based floors so a blocking control cannot be reported as low risk.

## Grounding

```json
{
  "grounding": {
    "citation_required": true,
    "citation_min_words": 25,
    "minimum_token_length": 4
  }
}
```

| Field | Meaning |
| --- | --- |
| `citation_required` | Requires source references for sufficiently long output |
| `citation_min_words` | Output length at which citation rules apply |
| `minimum_token_length` | Ignores shorter tokens during lexical overlap calculation |

Local grounding measures normalized token overlap and checks citations such as `[source1]` or `[source:source1]`. It is a deterministic safety signal, not proof of factual correctness.

## Limits

```json
{
  "limits": {
    "max_input_chars": 32768,
    "max_output_chars": 32768,
    "max_context_chars": 65536,
    "max_context_items": 20
  }
}
```

Effective text limits are the lower value from runtime configuration and policy. `max_context_items` cannot exceed 100.

## Profiles document

```json
{
  "schema_version": 2,
  "profiles": {
    "example": {
      "aws_guardrail_required": false,
      "external_failure_action": "queue_for_review",
      "grounding_block_threshold": 0.05,
      "grounding_review_threshold": 0.35,
      "presidio_failure_action": "queue_for_review",
      "presidio_required": false,
      "prompt_attack_threshold": 0.5,
      "risk_thresholds": {
        "low": 0.25,
        "medium": 0.5,
        "high": 0.75
      }
    }
  }
}
```

Threshold values must be between `0.0` and `1.0`. Risk thresholds must increase from low to medium to high. The grounding block threshold cannot exceed the grounding review threshold.

## Policy digest

The reported digest is SHA-256 over canonical JSON containing both documents.

```powershell
python orchestrator.py policy-validate
```

Set the approved digest in production:

```powershell
$env:GUARDRAIL_EXPECTED_POLICY_SHA256 = "approved-64-character-sha256"
```

The runtime refuses to start when the loaded bundle differs.

## Change process

1. Edit policy in a review branch.
2. Run `policy-validate`.
3. Run the unit, self-test, red-team, and chaos suites.
4. Review new regex patterns for complexity and false positives.
5. Review action and risk changes with security and application owners.
6. Record the new policy version and digest.
7. Deploy in monitor mode when appropriate.
8. Pin the approved digest before enforcement.
