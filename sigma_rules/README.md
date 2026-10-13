# sigma_rules/

Improved detection rules in Sigma format, synthesized to close gaps the baseline rules in `detection/` missed.

Each rule targets `logsource: product: aws, service: cloudtrail` and should be validated against both the attack logs it's meant to catch and the benign baseline (see `evaluation/`) before being considered final.
