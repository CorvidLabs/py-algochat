---
change: CHG-0006-cover-all-installed-python-algochat-agent-integrations-in-the-verified-migration
artifact: testing
---

# Testing

- Run released SpecSync 5.0.1 strict validation at 100% coverage from the branch base range.
- Run lifecycle enforcement and confirm every accepted change is valid.
- Confirm all four agent integrations report installed.
- Run Ruff and the complete Pytest suite through Fledge.
- Confirm no files under `src/` or `tests/` changed.
