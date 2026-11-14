- **`python3 scripts/check.py` runs the PR checks in one command** (#760): validate, ruff on CI's
  exact paths, the shard-partition check and the full suite as parallel `shard-tests.py` shards,
  reporting each step as it finishes and every red step's own output. `--no-suite` is the fast
  loop. AGENTS.md and CONTRIBUTING.md name it, and CONTRIBUTING's ruff line lints `evals/demo`
  (it named a `demo/` that no longer exists and failed as written).
