"""PurpleLoop entry point.

Orchestrates the end-to-end pipeline: run simulated attacks, capture
CloudTrail logs, evaluate baseline + Sigma rule coverage, and (optionally)
run the mutation-engine evasion search.

This is a placeholder — fill in each stage as the corresponding module
under detection/, evaluation/, sigma_rules/, and mutation_engine/ is built.
"""


def main() -> None:
    raise NotImplementedError("PurpleLoop pipeline not yet implemented.")


if __name__ == "__main__":
    main()
