# nuclei_templates/

Nuclei-format YAML attack templates for PurpleLoop's purple-team simulation pipeline.

## Overview

These templates define **reproducible, parameterised attack scenarios** against AWS
infrastructure.  Each template maps to one or more MITRE ATT&CK techniques and
generates synthetic CloudTrail-style log events that feed into the `detection/` and
`sigma_rules/` evaluation pipeline.

## Template Categories

| Directory | MITRE Tactic | Description |
|---|---|---|
| `aws-iam-privesc/` | Privilege Escalation (TA0004) | IAM policy attachment, role assumption, access-key creation |
| `aws-s3-exfil/` | Exfiltration (TA0010) | Bulk S3 object reads, bucket policy manipulation, cross-account replication |
| `aws-cloudtrail-tamper/` | Defense Evasion (TA0005) | Trail deletion, logging disable, event selector manipulation |
| `aws-credential-access/` | Credential Access (TA0006) | STS token abuse, SSO backdoor, federation endpoint attacks |
| `aws-persistence/` | Persistence (TA0003) | Lambda backdoor, IAM user creation, access key rotation abuse |

## Integration with PurpleLoop

```
nuclei_templates/ ──▶ simulation/nuclei_runner.py ──▶ logs/ (CloudTrail JSON)
                                                          │
                              ┌────────────────────────────┘
                              ▼
                    detection/ + sigma_rules/ ──▶ evaluation/coverage.csv
                              │
                              ▼
                    mutation_engine/ ◀── feeds evasion variants back as new templates
```

## Usage

```bash
# Run all templates (dry-run, synthetic logs only)
python simulation/nuclei_runner.py --templates nuclei_templates/ --dry-run --output logs/

# Run a specific category
python simulation/nuclei_runner.py --templates nuclei_templates/aws-iam-privesc/ --output logs/

# Run with mutation variants
python simulation/nuclei_runner.py --templates nuclei_templates/ --mutate --rounds 10 --output logs/
```

## Template Variables

| Variable | Default | Description |
|---|---|---|
| `{{delay_seconds}}` | `0` | Inter-request delay to evade rate-based detections |
| `{{batch_size}}` | `100` | Number of objects/actions per burst |
| `{{session_name}}` | `red-team-sim` | STS session name used in AssumeRole |
| `{{user_agent}}` | `aws-cli/2.x` | User-agent string for API calls |
| `{{target_account}}` | `env:TARGET_ACCOUNT` | AWS account ID for cross-account scenarios |
