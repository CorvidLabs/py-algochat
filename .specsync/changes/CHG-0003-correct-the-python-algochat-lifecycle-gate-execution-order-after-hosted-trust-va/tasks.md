---
change: CHG-0003-correct-the-python-algochat-lifecycle-gate-execution-order-after-hosted-trust-va
artifact: tasks
---

# Tasks

- [x] Reproduce and identify the hosted missing-`specsync` failure from the Trust job log.
- [x] Add the immutable SpecSync 5.0.1 lifecycle gate before Trust.
- [x] Restore `.trust.toml` lifecycle verification to the native-only Fledge lane.
- [x] Correct the canonical verification requirement and test mapping to describe the real execution order.
- [x] Prepare strict SpecSync, Ruff, and Pytest verification without changing product source or tests.
