---
id: CHG-0006-cover-all-installed-python-algochat-agent-integrations-in-the-verified-migration
state: accepted
type: bug_fix
base_commit: eb6cc1c64faae33db75602cc3e2098e5db0d7e04
---

# Cover all installed Python AlgoChat agent integrations in the verified migration

## Intent

Cover all installed Python AlgoChat agent integrations in the verified migration

## Affected Canonical Specs

- None

## Acceptance Criteria

- Strict hosted-equivalent SpecSync accepts every meaningful Claude
- Codex
- Cursor
- and Gemini integration path as covered; all four agent integrations report installed; no source or test files change

## No-spec Rationale

This change records lifecycle coverage for the already-installed agent integration files after they became meaningful paths; it does not change the AlgoChat protocol, canonical contract, source, tests, or public API.
