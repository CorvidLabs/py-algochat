---
module: algochat
version: 1
status: active
files:
  - src/algochat/__init__.py
  - src/algochat/blockchain.py
  - src/algochat/client.py
  - src/algochat/crypto.py
  - src/algochat/envelope.py
  - src/algochat/keys.py
  - src/algochat/models.py
  - src/algochat/psk_crypto.py
  - src/algochat/psk_envelope.py
  - src/algochat/psk_exchange.py
  - src/algochat/psk_ratchet.py
  - src/algochat/psk_state.py
  - src/algochat/psk_types.py
  - src/algochat/queue.py
  - src/algochat/signature.py
  - src/algochat/storage.py
  - src/algochat/types.py

db_tables: []
depends_on: []
---

# Python AlgoChat Protocol

## Purpose

Implement encrypted AlgoChat messaging for Algorand in Python, including interoperable envelopes, X25519 and PSK cryptography, replay-safe ratchet state, blockchain transport abstractions, queues, signatures, and key storage.

## Public API

The `algochat` package exports the existing client, model, cryptographic, envelope, PSK, queue, signature, storage, and transport interfaces. This governance migration documents and verifies those interfaces without changing their runtime behavior.

| Export | Contract |
|---|---|
| `derive_keys_from_seed` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `generate_ephemeral_keypair` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `encrypt_message` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `decrypt_message` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `encode_envelope` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `decode_envelope` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `is_chat_message` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `ChatEnvelope` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `DecryptedContent` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `sign_encryption_key` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `verify_encryption_key` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `verify_encryption_key_bytes` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `fingerprint` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `SIGNATURE_SIZE` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `ReplyContext` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `MessageDirection` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `Message` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `Conversation` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `DiscoveredKey` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `SendOptions` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `SendResult` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `PendingStatus` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `PendingMessage` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `MessageCache` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `InMemoryMessageCache` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `PublicKeyCache` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `EncryptionKeyStorage` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `InMemoryKeyStorage` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `FileKeyStorage` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `AlgoChatError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `InvalidPublicKeyError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `KeyDerivationError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `InvalidSignatureError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `EncryptionError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `DecryptionError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `InvalidEnvelopeError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `IndexerNotConfiguredError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `PublicKeyNotFoundError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `UnverifiedKeyError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `InvalidRecipientError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `TransactionError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `InsufficientBalanceError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `KeyNotFoundError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `StorageError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `MessageNotFoundError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `MINIMUM_PAYMENT` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `QueueConfig` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `SendQueue` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `AlgorandConfig` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `TransactionInfo` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `NoteTransaction` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `SuggestedParams` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `AccountInfo` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `AlgodClient` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `IndexerClient` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `discover_encryption_key` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `AlgoChatConfig` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `AlgoChat` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `PSK_VERSION` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `PSK_PROTOCOL_ID` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `PSK_HEADER_SIZE` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `PSK_TAG_SIZE` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `PSK_ENCRYPTED_SENDER_KEY_SIZE` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `PSK_MAX_PAYLOAD_SIZE` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `PSK_SESSION_SIZE` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `PSK_COUNTER_WINDOW` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `PSKEnvelope` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `derive_session_psk` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `derive_position_psk` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `derive_psk_at_counter` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `derive_hybrid_symmetric_key` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `derive_sender_key` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `encode_psk_envelope` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `decode_psk_envelope` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `is_psk_message` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `PSKEnvelopeError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `PSKState` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `validate_counter` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `record_receive` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `advance_send_counter` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `create_psk_exchange_uri` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `parse_psk_exchange_uri` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `encrypt_psk_message` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `decrypt_psk_message` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `PSKEncryptionError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `PSKDecryptionError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `InvalidAddressError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `EnvelopeError` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `x25519_ecdh` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `public_key_to_bytes` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `public_key_from_bytes` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `PROTOCOL_VERSION` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `PROTOCOL_ID` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `HEADER_SIZE` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `TAG_SIZE` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `ENCRYPTED_SENDER_KEY_SIZE` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `MAX_PAYLOAD_SIZE` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `NONCE_SIZE` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `PUBLIC_KEY_SIZE` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `KEY_DERIVATION_SALT` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `KEY_DERIVATION_INFO` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `ENCRYPTION_INFO_PREFIX` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |
| `SENDER_KEY_INFO_PREFIX` | Existing exported AlgoChat API governed by the subsystem invariants and stable requirements below. |


### Standard Protocol and Models

`derive_keys_from_seed`, `generate_ephemeral_keypair`, `encrypt_message`, `decrypt_message`, `encode_envelope`, `decode_envelope`, `is_chat_message`, `ChatEnvelope`, `DecryptedContent`, `sign_encryption_key`, `verify_encryption_key`, `verify_encryption_key_bytes`, `fingerprint`, `SIGNATURE_SIZE`, `ReplyContext`, `MessageDirection`, `Message`, `Conversation`, `DiscoveredKey`, `SendOptions`, `SendResult`, `PendingStatus`, and `PendingMessage` expose the existing standard message lifecycle, result models, and key-authentication surface.

### Storage, Queue, Transport, and Client

`MessageCache`, `InMemoryMessageCache`, `PublicKeyCache`, `EncryptionKeyStorage`, `InMemoryKeyStorage`, `FileKeyStorage`, `MINIMUM_PAYMENT`, `QueueConfig`, `SendQueue`, `AlgorandConfig`, `TransactionInfo`, `NoteTransaction`, `SuggestedParams`, `AccountInfo`, `AlgodClient`, `IndexerClient`, `discover_encryption_key`, `AlgoChatConfig`, and `AlgoChat` expose the existing persistence, delivery, Algorand transport, discovery, and high-level client boundaries.

### Errors

`AlgoChatError`, `InvalidPublicKeyError`, `KeyDerivationError`, `InvalidSignatureError`, `EncryptionError`, `DecryptionError`, `InvalidEnvelopeError`, `IndexerNotConfiguredError`, `PublicKeyNotFoundError`, `UnverifiedKeyError`, `InvalidRecipientError`, `TransactionError`, `InsufficientBalanceError`, `KeyNotFoundError`, `StorageError`, `MessageNotFoundError`, `InvalidAddressError`, and `EnvelopeError` preserve explicit failure categories rather than collapsing protocol, transport, or persistence failures.

### PSK Protocol

`PSK_VERSION`, `PSK_PROTOCOL_ID`, `PSK_HEADER_SIZE`, `PSK_TAG_SIZE`, `PSK_ENCRYPTED_SENDER_KEY_SIZE`, `PSK_MAX_PAYLOAD_SIZE`, `PSK_SESSION_SIZE`, `PSK_COUNTER_WINDOW`, `PSKEnvelope`, `derive_session_psk`, `derive_position_psk`, `derive_psk_at_counter`, `derive_hybrid_symmetric_key`, `derive_sender_key`, `encode_psk_envelope`, `decode_psk_envelope`, `is_psk_message`, `PSKEnvelopeError`, `PSKState`, `validate_counter`, `record_receive`, `advance_send_counter`, `create_psk_exchange_uri`, `parse_psk_exchange_uri`, `encrypt_psk_message`, `decrypt_psk_message`, `PSKEncryptionError`, and `PSKDecryptionError` expose PSK v1.1 derivation, envelope, exchange, replay-state, and authenticated encryption behavior.

### Key and Wire Constants

`x25519_ecdh`, `public_key_to_bytes`, `public_key_from_bytes`, `PROTOCOL_VERSION`, `PROTOCOL_ID`, `HEADER_SIZE`, `TAG_SIZE`, `ENCRYPTED_SENDER_KEY_SIZE`, `MAX_PAYLOAD_SIZE`, `NONCE_SIZE`, `PUBLIC_KEY_SIZE`, `KEY_DERIVATION_SALT`, `KEY_DERIVATION_INFO`, `ENCRYPTION_INFO_PREFIX`, and `SENDER_KEY_INFO_PREFIX` preserve the existing interoperable key conversion, field sizing, identifiers, and derivation domains.

## Invariants

1. Standard messages use the existing X25519, HKDF-SHA256, and ChaCha20-Poly1305 construction and remain decryptable by the intended recipient and originating sender.
2. Encoded standard and PSK envelopes preserve the established cross-implementation wire format.
3. PSK counters derive deterministic per-message keys, reject replays, allow the configured out-of-order window, and prune obsolete receive state.
4. File key storage encrypts private material at rest and preserves the interoperable salt, nonce, ciphertext, and tag layout; in-memory storage remains test-only.
5. Blockchain, queue, and client abstractions preserve asynchronous ordering and do not silently discard protocol errors.

## Behavioral Examples

```text
Given two AlgoChat key pairs and an authenticated plaintext
When the sender encrypts and encodes an envelope for the recipient
Then the recipient decodes and decrypts the original plaintext and tampering fails authentication
```

## Error Cases

| Error | When | Behavior |
|---|---|---|
| Invalid envelope | Encoded data has an unsupported marker, length, or field layout | Reject decoding without returning unauthenticated plaintext |
| Authentication failure | Ciphertext, associated data, key material, or signature is invalid | Raise the existing protocol error |
| Replay | A PSK receive counter was already processed or is outside the accepted window | Reject the message and preserve valid state |
| Missing key or message | Storage, queue, or transport lookup cannot resolve the requested item | Return or raise the existing explicit absence result |

## Dependencies

- Python 3.10 or newer
- `cryptography` for X25519, ChaCha20-Poly1305, HKDF, AES-GCM, and PBKDF2 primitives
- Algorand-compatible transaction and note transport supplied through the existing abstractions

## Change Log

| Version | Date | Changes |
|---|---|---|
| 1 | 2026-07-13 | Initial active contract for the existing Python implementation |
