---
change: CHG-0001-adopt-specsync-5-0-1-and-trust-1-0-0-governance-for-the-python-algochat-implemen
artifact: testing
---

# Testing

- Run Ruff against src and tests.\n- Run all pytest tests in the declared development environment.\n- Preserve the Python 3.10, 3.11, and 3.12 hosted matrix.\n- Keep cross-implementation tests present even when external fixture sets cause documented skips.\n- Run SpecSync strict validation, all-agent status, Trust doctor, and Trust verify.

