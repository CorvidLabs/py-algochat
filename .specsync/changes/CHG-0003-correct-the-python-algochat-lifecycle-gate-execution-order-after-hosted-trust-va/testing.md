---
change: CHG-0003-correct-the-python-algochat-lifecycle-gate-execution-order-after-hosted-trust-va
artifact: testing
---

# Testing

- `REQ-algochat-005`: the pinned SpecSync step must pass strict lifecycle validation before Trust, and the Trust lifecycle must run the native-only Fledge lane.
- Run `specsync check --strict --require-coverage 100 --force` and lifecycle validation with all active changes complete.
- Run `fledge lanes run verify`; this must execute Ruff and the complete Pytest suite without invoking SpecSync recursively.
- Confirm all four agent integrations remain installed and Trust doctor reports the standard policy healthy.
- Confirm the hosted `trust` job completes the pinned SpecSync step before the pinned Trust step.
- Confirm `git diff` contains no changes under `src/` or `tests/`.
