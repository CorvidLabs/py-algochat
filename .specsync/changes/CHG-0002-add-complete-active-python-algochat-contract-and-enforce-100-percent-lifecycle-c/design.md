---
change: CHG-0002-add-complete-active-python-algochat-contract-and-enforce-100-percent-lifecycle-c
artifact: design
---

# Design

Use one active `algochat` module for all 17 package files because they jointly implement one wire protocol. Record five stable behavioral requirements, map them to existing focused tests, protect public documentation and agent policy, keep Ruff and Pytest in Fledge, and enforce strict SpecSync separately as Trust's lifecycle command.
