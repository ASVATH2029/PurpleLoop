# mutation_engine/

Attack-variation generator and scoring logic — the "RL-lite" evasion search.

Takes one attack chain, generates N mutations (varying delay, batch size, identity/session reuse), and scores each against the full rule set from `detection/` + `sigma_rules/` to find mutations that evade current detections. The reward formulation (`reward = objective_completion - detection_penalty`) is documented here as a design artifact for a future trained-policy version, not implemented as real RL yet.
