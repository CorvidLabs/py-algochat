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

- Always-run standard and PSK envelope vectors round-trip and preserve their protocol markers.
- When the separate sibling fixture repository is available, the cross-implementation suite accepts its encoded
  Swift, TypeScript, Rust, Kotlin, and Python fixtures; absent sibling fixtures are reported as skips and are not
  counted as required native evidence.

### REQ-algochat-003

PSK ratchet state SHALL derive deterministic per-counter keys, reject replayed counters, accept configured out-of-order delivery, and prune counters outside the receive window.

Acceptance Criteria

- PSK derivation, exchange, state, replay, window, and pruning tests pass.

### REQ-algochat-004

Key storage, queues, signatures, blockchain transport, and the high-level client SHALL preserve explicit asynchronous success and failure behavior without silently losing messages or private material.

Acceptance Criteria

- Storage, queue, signature, blockchain, and client tests pass, including absence and failure cases.

### REQ-algochat-005

Native verification SHALL lint the implementation and run the complete deterministic Python test suite, while the pinned SpecSync workflow gate separately enforces the verified SDD lifecycle at 100% source coverage.

Acceptance Criteria

- The Fledge verification lane passes Ruff and Pytest without external credentials, and the pinned SpecSync 5.0.1 action passes strict lifecycle validation at 100% coverage before Trust runs.

### REQ-algochat-006

AlgoChat notes SHALL be at most 4096 bytes. A standard plaintext of 3954 bytes and a PSK plaintext of 3950 bytes SHALL encode to exactly 4096 bytes. Plaintexts of 882 and 878 bytes SHALL still encrypt, and those notes SHALL be at most 1024 bytes. One byte past either maximum SHALL fail before a transaction is built. A note payment fee at a minimum fee of 1000 microAlgos SHALL be 1000, 1098, and 1308 for notes of 1024, 2000, and 4096 bytes.

Acceptance Criteria

- Standard and PSK size tests accept 882 and 878 byte plaintexts, encode the new maxima to exactly 4096 bytes, and reject one extra byte before encoding.
- Fee tests at minimum fee 1000 expect 1000, 1098, and 1308 microAlgos for notes of 1024, 2000, and 4096 bytes.

