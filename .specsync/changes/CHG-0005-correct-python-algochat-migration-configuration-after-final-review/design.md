---
change: CHG-0005-correct-python-algochat-migration-configuration-after-final-review
artifact: design
---

# Design

Keep corrections local to development and governance configuration. Add Ruff explicitly to Fledge's install command; treat `specs/` and the Claude, Codex, Cursor, and Gemini directories as meaningful; use Gemini's documented `{{args}}` substitution directly; and classify the complete create-spec input after removing `--minimal`, using it as a module name only when it is a single whitespace-free identifier.
