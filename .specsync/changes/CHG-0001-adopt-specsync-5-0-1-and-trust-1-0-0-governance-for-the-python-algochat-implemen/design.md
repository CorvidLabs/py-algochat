---
change: CHG-0001-adopt-specsync-5-0-1-and-trust-1-0-0-governance-for-the-python-algochat-implemen
artifact: design
---

# Design

Retain CI and publishing unchanged and add an independent trust job on Python 3.12. Use standard Trust with blocking risk, soft provenance, advisory contract threshold 0, and Atlas disabled. The Fledge verify lane runs Ruff and the full pytest suite after workflow dependency setup.

