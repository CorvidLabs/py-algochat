---
change: CHG-0005-correct-python-algochat-migration-configuration-after-final-review
artifact: testing
---

# Testing

- Validate `fledge.toml`, `.specsync/sdd.json`, and both Gemini TOML command files parse successfully.
- Confirm every create-spec prompt classifies the complete remaining input before selecting a module name.
- Run strict SpecSync at 100% coverage and lifecycle enforcement.
- Confirm all four agent integrations remain installed.
- Run the Fledge verification lane, Trust doctor, Ruff, and the complete Pytest suite.
- Confirm no files under `src/` or `tests/` changed.
