---
change: CHG-0007-correct-python-algochat-contract-rows-fixture-evidence-and-free-text-agent-gui
artifact: design
---

# Design

Use the implementation as the source of truth. `DiscoveredKey` documents `public_key` and `is_verified` only;
`SendOptions` documents confirmation/indexer waits, timeouts, and reply context; `SendResult` documents `txid` and
the sent `Message`. Discovery is described as first-valid in indexer result order. Native vector tests remain required,
while cross-implementation fixtures are conditional on the separate sibling checkout. Regenerate all four agent
integrations from the corrected shared SpecSync installer rather than preserving repository-specific prompt patches.
