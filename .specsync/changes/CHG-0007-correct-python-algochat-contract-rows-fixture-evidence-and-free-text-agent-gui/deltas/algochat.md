# Correct contract and fixture evidence

## MODIFIED

### REQUIREMENT REQ-algochat-002

Standard and PSK envelopes SHALL preserve the established cross-implementation binary format and message markers.

Acceptance Criteria

- Always-run standard and PSK envelope vectors round-trip and preserve their protocol markers.
- When the separate sibling fixture repository is available, the cross-implementation suite accepts its encoded
  Swift, TypeScript, Rust, Kotlin, and Python fixtures; absent sibling fixtures are reported as skips and are not
  counted as required native evidence.

## ADDED

### SPEC SECTION Corrected Model and Discovery Contracts

- `DiscoveredKey` stores an X25519 public key and its Ed25519 verification state; it does not store an address or source transaction.
- `SendOptions` configures confirmation and indexer waits, their timeouts, and optional reply context; it does not publish keys.
- `SendResult` stores the transaction identifier and resulting sent `Message`; it does not expose a confirmed-round field.
- `discover_encryption_key` returns the first valid key announcement in indexer result order and does not promise latest-key ordering.
