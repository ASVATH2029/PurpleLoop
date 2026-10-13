# simulation/

Controlled attack scenarios and normal/benign test activity.

- Attack chains (IAM privilege escalation, S3 exfiltration, CloudTrail tampering) and their variants, executed via the scoped `red-team-sim` identity.
- Benign baseline activity scripts used to generate non-malicious CloudTrail noise for false-positive testing.

All scripts here are intended to run only against a lab/sandbox AWS account you control, never production infrastructure.
