# PurpleLoop

A purple-team detection-engineering demo on AWS: simulate attacker techniques, measure how much baseline detection coverage misses, close the gaps with targeted Sigma rules, and run a lightweight evasion search that foreshadows an RL-based attacker adapting to those new rules.

## What this proves

1. Attack technique variants silently evade baseline detection rules.
2. Targeted Sigma rules close those gaps without flooding on benign traffic.
3. A simple evasion-search loop over attack parameters previews what an RL-based attacker would do next — adapt until it finds a variant the current rules miss again.

## Layout

| Path | Purpose |
|---|---|
| `config/` | AWS configuration and environment settings |
| [`nuclei_templates/`](nuclei_templates/README.md) | Declarative Nuclei attack templates for AWS threat scenarios |
| `simulation/` | Controlled attack scenarios, dry-run synthesizers, and benign activity |
| `logs/` | Captured/sample CloudTrail logs and test datasets |
| `detection/` | Baseline detection rules and log-analysis functions |
| `sigma_rules/` | Synthesized Sigma rules that close baseline gaps |
| `evaluation/` | Rule validation, coverage calculation, false-positive analysis |
| `mutation_engine/` | Attack-variant generator and evasion scoring ("RL-lite") |
| `dashboard/` | Dashboard and alert display |
| `main.py` | Pipeline entry point |

## Attack Emulation

Adversary emulation scenarios are defined as declarative YAML templates under [`nuclei_templates/`](nuclei_templates/README.md). These templates cover multi-step AWS attack chains across five MITRE ATT&CK tactics:
- Privilege Escalation: IAM policy attachment and multi-hop role assumption chains
- Persistence: Access key creation and serverless Lambda backdoors
- Credential Access: STS token abuse and wildcard federation policies
- Exfiltration: S3 bucket policy manipulation and bulk object reads
- Defense Evasion: CloudTrail logging disruption and trail destruction

For a comprehensive technical walkthrough of each template, the CloudTrail telemetry footprint generated, and the genetic mutation engine, refer to the [Nuclei Templates Guide](nuclei_templates/README.md).

Quick test run (dry-run mode, no AWS credentials required):

```bash
python simulation/nuclei_runner.py --templates nuclei_templates/ --dry-run --output logs/
```

## Status

Scaffolding and attack simulation runner implemented. All live AWS activity is intended to run against a dedicated lab/sandbox account under a scoped `red-team-sim` identity, never production infrastructure.

## Setup

```bash
pip install -r requirements.txt
```

AWS credentials and config live outside this repo (environment variables / `~/.aws/credentials`) — see `config/README.md`.
