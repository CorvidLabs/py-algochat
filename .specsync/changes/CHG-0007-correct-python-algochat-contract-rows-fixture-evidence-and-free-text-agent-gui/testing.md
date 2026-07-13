---
change: CHG-0007-correct-python-algochat-contract-rows-fixture-evidence-and-free-text-agent-gui
artifact: testing
---

# Testing

- Compare every corrected contract row with `src/algochat/models.py` and `src/algochat/blockchain.py`.
- Run the Fledge verification lane for Ruff and the deterministic Pytest suite.
- Run strict SpecSync validation at the committed 100% file and LOC threshold.
- Confirm `specsync agents status` reports Claude, Cursor, Codex, and Gemini installed.
- Confirm generated create-change guidance quotes `"<answer>"` and Gemini uses `{{args}}` only.
- Confirm no `src/` or `tests/` files differ from the PR's prior implementation head.

## Requirement Evidence

- `REQ-algochat-002`: always-run vector tests in `test_models.py`, `test_psk.py`, and `test_vectors.py`; optional
  cross-implementation evidence in `test_cross_impl.py` only when the sibling fixture checkout exists.
