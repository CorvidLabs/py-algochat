---
change: CHG-0002-add-complete-active-python-algochat-contract-and-enforce-100-percent-lifecycle-c
artifact: design
---

# Design

Use one active `algochat` module for all 17 package files because they jointly implement one wire protocol. Record five stable behavioral requirements, map them to existing focused tests, protect public documentation and agent policy, and run SpecSync lifecycle validation before Ruff and Pytest in the existing Fledge lane.
