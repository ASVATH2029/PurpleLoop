# evaluation/

Rule validation, coverage calculations, and false-positive analysis.

Expected contents: the `validate(rule_fn, log) -> bool` harness, the script that builds `coverage.csv` (technique, variant, rule_id, caught, confidence), and false-positive checks against `logs/benign_baseline.json`.
