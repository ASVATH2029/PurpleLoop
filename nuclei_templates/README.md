# Nuclei Attack Templates for AWS Purple Teaming

This directory contains YAML templates written in an extended Nuclei syntax designed for adversary emulation against Amazon Web Services (AWS) environments. In the PurpleLoop workflow, these templates serve as executable threat models: they describe multi-step attack scenarios, map to the MITRE ATT&CK framework, define the exact telemetry signature an attack leaves in AWS CloudTrail, and supply matchers for automated detection scoring.

---

## Architecture and Design Philosophy

Traditional application security tooling uses Nuclei to send HTTP requests looking for known vulnerabilities. PurpleLoop adapts this declarative template model for cloud detection engineering.

Instead of testing whether a single web endpoint returns a specific status code, these templates define:
1. Multi-step API sequences that represent realistic adversary behavior (reconnaissance, privilege escalation, persistence, exfiltration, and defense evasion).
2. Synthetic CloudTrail event generators so detections can be validated immediately without incurring AWS billable API calls or needing full lab infrastructure.
3. Live execution definitions that can be executed against an isolated AWS sandbox when real API calls are desired.
4. Mutation parameters that allow an evasion search engine to vary delays, user-agents, IP addresses, and batch sizes to test if detection rules are fragile.

### Telemetry Pipeline Flow

```
nuclei_templates/*.yaml
          |
          v
simulation/nuclei_runner.py
    |-- Dry-run mode: synthesizes CloudTrail JSON logs locally
    |-- Live mode: executes commands against an AWS lab account
    |-- Mutation mode: applies parameter jitter and evasion variants
          |
          v
logs/nuclei_sim_<timestamp>.json
          |
          +---------------------------------------+
          |                                       |
          v                                       v
detection/ (Baseline rules)             sigma_rules/ (Synthesized rules)
          |                                       |
          +-------------------+-------------------+
                              |
                              v
                   evaluation/coverage.csv
                              |
                              v
              mutation_engine/ (Evasion loop)
```

---

## Template Schema Specification

Every template follows a standardised structure with five primary blocks: id, info, attack, matchers / extractors, and variables.

### 1. Metadata Block (id, info)

Identifies the scenario, risk level, and MITRE mapping:

```yaml
id: purpleloop-iam-admin-policy-attachment
info:
  name: IAM Admin Policy Attachment — Privilege Escalation
  author: PurpleLoop
  severity: critical
  description: Simulates an attacker attaching AdministratorAccess to a compromised user.
  reference:
    - https://attack.mitre.org/techniques/T1098/001/
  tags: aws,iam,privilege-escalation,cloudtrail
  metadata:
    mitre_attack:
      tactic: "TA0004 - Privilege Escalation"
      technique: "T1098.001 - Account Manipulation: Additional Cloud Credentials"
    purpleloop:
      attack_chain: iam-privesc
      variant: baseline
      severity_score: 9.5
```

### 2. Attack Execution Block (attack)

Contains an ordered list of operations under steps. Each step defines the AWS action name, description, execution parameters, optional pacing delay, and the full CloudTrail event structure generated during dry-run simulation:

```yaml
attack:
  type: aws-api
  steps:
    - action: iam:AttachUserPolicy
      description: Attach AdministratorAccess policy to target user
      parameters:
        UserName: "{{session_name}}"
        PolicyArn: "arn:aws:iam::aws:policy/AdministratorAccess"
      delay: "{{delay_seconds}}"
      cloudtrail_event:
        eventName: AttachUserPolicy
        eventSource: iam.amazonaws.com
        sourceIPAddress: "{{source_ip}}"
        userAgent: "{{user_agent}}"
        requestParameters:
          userName: "{{session_name}}"
          policyArn: "arn:aws:iam::aws:policy/AdministratorAccess"
```

### 3. Matchers and Extractors (matchers, extractors)

Matchers define the logical condition that confirms the attack executed and produced the expected security log footprint:

```yaml
matchers:
  - type: cloudtrail
    name: admin-policy-attached
    condition: and
    fields:
      - eventName == "AttachUserPolicy"
      - requestParameters.policyArn contains "AdministratorAccess"

extractors:
  - type: json
    name: escalated-user
    json:
      - ".requestParameters.userName"
```

### 4. Parametric Variables (variables)

Variables are template placeholders that can be overridden at runtime or perturbed by the mutation engine to test evasion:

```yaml
variables:
  delay_seconds: "0"
  batch_size: "1"
  source_ip: "198.51.100.42"
  user_agent: "aws-cli/2.15.0 Python/3.11.6 Linux/5.15.0"
  session_name: "red-team-sim"
  target_account: "123456789012"
```

---

## Detailed Scenario Breakdown

The current suite contains eight attack templates across five MITRE ATT&CK tactics.

### 1. Privilege Escalation (TA0004)

#### Template: aws-iam-privesc/iam-admin-policy-attachment.yaml
- Scenario: An attacker who has compromised a low-privilege IAM user checks their own identity (iam:GetUser), checks what policies are currently attached (iam:ListAttachedUserPolicies), and then attaches the AWS managed AdministratorAccess policy to themselves (iam:AttachUserPolicy).
- Real-World Pattern: Common in leaked developer credentials where the developer was granted broad iam:* permissions without permission boundaries.
- Telemetry Footprint: Generates GetUser, ListAttachedUserPolicies, and AttachUserPolicy events in iam.amazonaws.com.
- Primary Detection Target: Any AttachUserPolicy event where policyArn matches arn:aws:iam::aws:policy/AdministratorAccess or any customer policy granting *:* permissions.
- Evasion Vectors Tested: Altering the user-agent string, splitting steps across multiple hours via delay_seconds, or substituting a custom inline policy rather than the well-known managed policy ARN.

#### Template: aws-iam-privesc/iam-role-assumption-chain.yaml
- Scenario: An attacker jumps through multiple IAM roles (sts:AssumeRole -> sts:AssumeRole) before carrying out sensitive reconnaissance (iam:ListUsers).
- Real-World Pattern: Adversaries chain cross-account or cross-service roles to break analyst attribution, evade simple IP-based alerts, and bypass basic IAM anomaly detection that only monitors single-hop session names.
- Telemetry Footprint: Sequence of AssumeRole calls in sts.amazonaws.com followed by management plane calls from temporary assumed-role credentials where userIdentity.type is AssumedRole.
- Primary Detection Target: Correlating sequential AssumeRole events where the caller of the second role assumption is the session identity created by the first.
- Evasion Vectors Tested: Inter-hop delay increments, varying session names, and hopping across different regions.

---

### 2. Persistence (TA0003)

#### Template: aws-iam-privesc/iam-access-key-creation.yaml
- Scenario: Once inside, the adversary establishes permanent access by creating a new programmatic access key (iam:CreateAccessKey) and establishing console login credentials (iam:CreateLoginProfile) on a user identity.
- Real-World Pattern: Stolen temporary credentials expire quickly; adversaries create long-lived API keys to maintain access even if the initial compromised session is revoked.
- Telemetry Footprint: CreateAccessKey and CreateLoginProfile calls logged by iam.amazonaws.com.
- Primary Detection Target: CreateAccessKey calls executed by assumed roles or third-party federated sessions, or creation of access keys on dormant or administrator accounts.
- Evasion Vectors Tested: Randomising the access key name, issuing calls outside standard operating hours, and rotating source IP addresses between creation and usage.

#### Template: aws-persistence/lambda-backdoor-function.yaml
- Scenario: The attacker creates an IAM service role (iam:CreateRole), attaches administrator permissions (iam:AttachRolePolicy), uploads a malicious Lambda function (lambda:CreateFunction), and sets up an Amazon EventBridge rule (events:PutRule and events:PutTargets) to trigger the function automatically on a schedule or upon specific cloud events.
- Real-World Pattern: Serverless persistence gives attackers code execution inside the target VPC without maintaining an active EC2 instance or persistent SSH connection.
- Telemetry Footprint: Events across three separate AWS services: iam.amazonaws.com, lambda.amazonaws.com, and events.amazonaws.com.
- Primary Detection Target: Creation of Lambda functions configured with broad IAM roles, coupled with EventBridge rules containing recurring rate or cron schedules.
- Evasion Vectors Tested: Function naming obfuscation, small code packages, and using generic CloudWatch event triggers.

---

### 3. Credential Access (TA0006)

#### Template: aws-credential-access/sts-token-abuse.yaml
- Scenario: The attacker requests temporary federated credentials using sts:GetFederationToken and sts:GetSessionToken while passing a custom inline policy that grants wide access (*:*). They then use these temporary tokens to enumerate account roles (iam:ListRoles).
- Real-World Pattern: GetFederationToken issues long-lasting temporary credentials (up to 36 hours) that bypass standard IAM session logging if teams only monitor standard IAM user access.
- Telemetry Footprint: GetFederationToken and GetSessionToken logged under sts.amazonaws.com, with inline policy text recorded in requestParameters.policy.
- Primary Detection Target: Calls to GetFederationToken from non-federated principals, especially where the inline policy parameter grants administrative or wildcard access.
- Evasion Vectors Tested: Requesting shorter token lifetimes to evade time-window aggregations, using non-standard session names, and obfuscating the inline policy string.

---

### 4. Exfiltration (TA0010)

#### Template: aws-s3-exfil/s3-bucket-policy-backdoor.yaml
- Scenario: The attacker reads an S3 bucket existing access policy (s3:GetBucketPolicy) and then replaces it (s3:PutBucketPolicy) with a policy allowing read and write access to an external, attacker-controlled AWS account.
- Real-World Pattern: Modifying bucket policies allows the attacker to pull data directly into an external environment using standard AWS credentials without making the bucket publicly readable, which avoids generic public-bucket security alarms.
- Telemetry Footprint: GetBucketPolicy and PutBucketPolicy logged under s3.amazonaws.com, with the modified JSON policy appearing in the request payload.
- Primary Detection Target: Any PutBucketPolicy call that adds external AWS account IDs or wildcards into the Principal field.
- Evasion Vectors Tested: Combining the backdoor with existing benign policy statements to blend in, or applying the change during scheduled deployment windows.

#### Template: aws-s3-exfil/s3-bulk-object-exfiltration.yaml
- Scenario: The attacker enumerates a sensitive data bucket (s3:ListObjectsV2), rapidly retrieves all objects in high-volume bursts (s3:GetObject), and copies them to a staging bucket (s3:PutObject).
- Real-World Pattern: Automated data theft following bucket discovery, often seen in extortion attacks.
- Telemetry Footprint: CloudTrail S3 data events (GetObject) generated at high frequency in a short time window.
- Primary Detection Target: High rate of GetObject API calls by a single principal within a sliding five-minute window, particularly on buckets containing classified data.
- Evasion Vectors Tested: Throttling downloads with delay_seconds to stay below rate thresholds, varying the batch_size, and rotating IP addresses or session tokens.

---

### 5. Defense Evasion (TA0005)

#### Template: aws-cloudtrail-tamper/cloudtrail-stop-logging.yaml
- Scenario: The attacker checks the status of logging configurations (cloudtrail:DescribeTrails), stops logging on the active trail (cloudtrail:StopLogging), modifies event selectors to exclude management events (cloudtrail:PutEventSelectors), and ultimately deletes the trail (cloudtrail:DeleteTrail).
- Real-World Pattern: Attackers disable audit logging immediately after gaining administrative control to hide all subsequent lateral movement and data theft.
- Telemetry Footprint: Sequential events in cloudtrail.amazonaws.com: DescribeTrails, StopLogging, PutEventSelectors, and DeleteTrail.
- Primary Detection Target: Any occurrence of StopLogging, DeleteTrail, or UpdateTrail on production logging configurations. This is among the highest-fidelity alert types in AWS environments.
- Evasion Vectors Tested: Modifying event selectors to filter out specific event names instead of stopping the trail outright, minimizing the chance of triggering binary trail-disabled alarms.

---

## The Simulation Runner (simulation/nuclei_runner.py)

The templates are executed and analyzed using the simulation runner, which supports three distinct operational modes.

### 1. Dry-Run Mode (Default)
In dry-run mode, the runner does not execute live network calls. Instead, it parses each template, resolves variables, and synthesizes syntactically correct AWS CloudTrail JSON events matching AWS API formats.

This allows engineers to:
- Generate realistic test fixtures instantly without requiring AWS credentials.
- Test detection rules and Sigma translations offline.
- Run continuous integration (CI) tests on rule sets.

```bash
python simulation/nuclei_runner.py --templates nuclei_templates/ --dry-run --output logs/
```

### 2. Live Execution Mode
When provided with AWS credentials and pointed at an isolated lab environment, the runner will execute the real API operations via the AWS CLI or boto3, capturing the actual logs returned by CloudTrail.

```bash
python simulation/nuclei_runner.py --templates nuclei_templates/aws-iam-privesc/ --output logs/
```

### 3. Mutation and Evasion Search Mode (--mutate)
The runner can systematically modify template variables across multiple simulation rounds to test if detection rules are overly sensitive to exact parameter values:
- delay_seconds: Injected between 0 and 300 seconds to test time-window and rate-limit rules.
- user_agent: Swapped between standard AWS CLI, Python SDK (boto3), custom tool names, and browser user-agents.
- source_ip: Rotated across IP ranges to test single-IP aggregation rules.
- batch_size: Scaled from 1 to 500 to evaluate volume thresholds.

```bash
python simulation/nuclei_runner.py --templates nuclei_templates/ --dry-run --mutate --rounds 5 --output logs/
```

The output summary report includes an evasion metric showing which matchers were bypassed by parameter mutation.

---

## Log Output Format

Every simulation run produces two files in the target directory:

1. **Event Stream Log** (logs/nuclei_sim_<timestamp>.json):
   Contains the raw, chronologically ordered CloudTrail event records. This file can be piped directly into SIEM tools, Athena, OpenSearch, or the PurpleLoop Sigma evaluation engine.

2. **Run Summary** (logs/nuclei_sim_<timestamp>_summary.json):
   Contains metadata for the run, including total events generated, template pass/fail counts, matcher trigger rates, and a breakdown of which matchers were triggered versus bypassed.

---

## Guide: Adding New Attack Templates

To add a new scenario to PurpleLoop:

1. Create a new YAML file under the appropriate aws-<category>/ directory.
2. Define a unique ID using the prefix purpleloop-<scenario-name>.
3. Fill in the metadata.mitre_attack fields with the valid tactic ID and technique ID.
4. Structure the attack.steps array:
   - Provide the AWS IAM action string (e.g. ec2:DescribeInstances).
   - Define realistic parameters.
   - Include the full cloudtrail_event dictionary representing what CloudTrail records for this action.
5. Add matchers that specify the exact field conditions required to detect the attack in log streams.
6. Declare default variables for all parameters that can be varied.
7. Validate your template by running the simulation runner in dry-run mode:

```bash
python simulation/nuclei_runner.py --templates nuclei_templates/<category>/<your-template>.yaml --dry-run --verbose
```
