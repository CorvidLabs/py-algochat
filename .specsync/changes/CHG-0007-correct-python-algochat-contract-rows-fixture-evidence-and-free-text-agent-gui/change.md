---
id: CHG-0007-correct-python-algochat-contract-rows-fixture-evidence-and-free-text-agent-gui
state: accepted
type: bug_fix
base_commit: 7949c9bbadac618e0ec1108e2055402a4c17b10e
---

# Correct Python AlgoChat contract rows, fixture evidence, and free-text agent guidance

## Intent

Correct Python AlgoChat contract rows, fixture evidence, and free-text agent guidance

## Affected Canonical Specs

- `algochat`

## Acceptance Criteria

- Canonical model and discovery contracts match the current dataclasses and first-valid indexer behavior; always-run vectors are required while optional sibling fixtures are reported without being claimed as native evidence; every installed agent quotes free-text change answers; strict SpecSync covers all 17 files and 3226 LOC and 103 exports; Ruff and all deterministic native tests pass with no product or test changes

## No-spec Rationale

Not applicable
