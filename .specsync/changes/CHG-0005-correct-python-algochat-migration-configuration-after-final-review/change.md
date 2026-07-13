---
id: CHG-0005-correct-python-algochat-migration-configuration-after-final-review
state: accepted
type: bug_fix
base_commit: 8fb14093995cb99c480e875a00a150bac8b38b36
---

# Correct Python AlgoChat migration configuration after final review

## Intent

Correct Python AlgoChat migration configuration after final review

## Affected Canonical Specs

- None

## Acceptance Criteria

- A clean Fledge install task installs Ruff before verification; specs and all four agent integration directories are meaningful SDD paths; Gemini passes rendered change arguments; create-spec commands classify the complete remaining input before choosing a module name; strict SpecSync and native tests pass with no source changes

## No-spec Rationale

These corrections affect development-tool bootstrap, meaningful-file policy, and generated agent command parsing only; the AlgoChat protocol, public API, canonical behavioral requirements, source, and tests are unchanged.
