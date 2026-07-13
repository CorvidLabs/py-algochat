---
change: CHG-0007-correct-python-algochat-contract-rows-fixture-evidence-and-free-text-agent-gui
artifact: context
---

# Context

Review of the migration PR found five documentation defects without any corresponding product-code defect. Three
public API rows described fields the Python dataclasses do not have, key discovery promised a latest-key ordering the
implementation does not establish, and the testing companion treated an optional sibling fixture checkout as native
required evidence. The generated agent integrations also passed free-text interview answers without quoting them.
This change corrects only specifications, test-evidence descriptions, and generated agent guidance.
