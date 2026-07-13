---
spec: algochat.spec.md
---

## Requirements

### REQ-algochat-001

Standard AlgoChat encryption and decryption SHALL preserve authenticated bidirectional message behavior using the existing key agreement and derivation construction.

Acceptance Criteria

- Standard crypto, key, envelope, and vector tests pass for valid messages and reject tampering or invalid keys.

### REQ-algochat-002

Standard and PSK envelopes SHALL preserve the established cross-implementation binary format and message markers.

Acceptance Criteria

- Envelope vectors round-trip and the cross-implementation test suite accepts the encoded fixtures.

### REQ-algochat-003

PSK ratchet state SHALL derive deterministic per-counter keys, reject replayed counters, accept configured out-of-order delivery, and prune counters outside the receive window.

Acceptance Criteria

- PSK derivation, exchange, state, replay, window, and pruning tests pass.

### REQ-algochat-004

Key storage, queues, signatures, blockchain transport, and the high-level client SHALL preserve explicit asynchronous success and failure behavior without silently losing messages or private material.

Acceptance Criteria

- Storage, queue, signature, blockchain, and client tests pass, including absence and failure cases.

### REQ-algochat-005

Native verification SHALL lint the implementation and run the complete deterministic Python test suite, while the Trust lifecycle gate separately enforces SpecSync at 100% source coverage.

Acceptance Criteria

- The Fledge verification lane passes Ruff and Pytest without external credentials, and the Trust lifecycle command passes strict SpecSync at 100% coverage.

