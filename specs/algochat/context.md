---
spec: algochat.spec.md
---

## Context

Python AlgoChat is one implementation of a shared encrypted messaging protocol. Its wire encodings, cryptographic construction, PSK ratchet rules, and fixtures must remain compatible with the sibling Swift, Rust, TypeScript, and Kotlin implementations.

Notes may be 4096 bytes. The standard header stays 126 bytes and the PSK header stays 130 bytes, with a 16-byte Poly1305 tag, so plaintext maxima are 3954 and 3950 bytes. A note payment fee is one minimum fee plus the consensus surcharge for bytes past 1024. This library does not sign with Falcon.
