# detection/

Baseline detection rules and log-analysis functions — the "typical SOC already has this" layer that the simulated attacks are tested against first.

Expected contents: pandas/JSON filter functions (e.g. IAM escalation, S3 burst-access, CloudTrail tamper exact-match rules) and the gap-analysis logic that produces `coverage.csv`.
