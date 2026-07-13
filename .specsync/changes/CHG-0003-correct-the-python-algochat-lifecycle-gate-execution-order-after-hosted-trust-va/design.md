---
change: CHG-0003-correct-the-python-algochat-lifecycle-gate-execution-order-after-hosted-trust-va
artifact: design
---

# Design

Run the immutable SpecSync 5.0.1 action immediately after Python dependencies are installed. It performs strict 100% contract validation and lifecycle enforcement, and leaves the downloaded binary on `PATH`. Then run immutable Trust 1.0.0 with its lifecycle command restored to the native-only Fledge `verify` lane. The ordering is finite: SpecSync validates the SDD lifecycle once, while Trust composes native Ruff/Pytest, contract, risk, and progressive provenance checks without recursively invoking SpecSync from the Fledge lane.
