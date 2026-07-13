---
change: CHG-0003-correct-the-python-algochat-lifecycle-gate-execution-order-after-hosted-trust-va
artifact: context
---

# Context

The first hosted run failed before native verification because Trust 1.0.0 executes `.trust.toml`'s lifecycle command before its contract component downloads SpecSync. Configuring that command as `specsync change check` therefore depends on a binary that does not yet exist on the runner. The source package, test suite, and canonical behavioral requirements are unchanged.
