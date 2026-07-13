# Precise Python AlgoChat export contracts

## MODIFIED

### SPEC SECTION Public API

The `algochat` package exports the existing client, model, cryptographic, envelope, PSK, queue, signature, storage, and transport interfaces. These contracts describe the current implementation without changing runtime behavior.

| Export | Contract |
|---|---|
| `derive_keys_from_seed` | Derives a deterministic X25519 private/public key pair from a 32-byte seed with HKDF-SHA256. |
| `generate_ephemeral_keypair` | Generates a random ephemeral X25519 key pair for message encryption. |
| `encrypt_message` | Encrypts authenticated message content for a recipient and returns a standard AlgoChat envelope. |
| `decrypt_message` | Decrypts a standard envelope as its intended recipient or originating sender. |
| `encode_envelope` | Serializes a standard `ChatEnvelope` into the protocol wire format. |
| `decode_envelope` | Validates and parses standard protocol bytes into a `ChatEnvelope`. |
| `is_chat_message` | Reports whether bytes have a structurally valid standard AlgoChat envelope header. |
| `ChatEnvelope` | Stores the standard envelope version, keys, nonce, ciphertext, and authentication tag. |
| `DecryptedContent` | Represents decrypted plaintext together with sender identity and key-publication metadata. |
| `sign_encryption_key` | Signs an encryption public key with an Ed25519 signing key. |
| `verify_encryption_key` | Verifies an encryption-key signature with an Ed25519 verification key. |
| `verify_encryption_key_bytes` | Verifies an encryption-key signature from raw Ed25519 public-key bytes. |
| `fingerprint` | Produces the human-readable fingerprint of an encryption public key. |
| `SIGNATURE_SIZE` | Defines the Ed25519 signature length as 64 bytes. |
| `ReplyContext` | Links a reply to the original transaction, sender, and optional excerpt. |
| `MessageDirection` | Distinguishes sent messages from received messages. |
| `Message` | Models a chat message, its transaction metadata, direction, status, and reply context. |
| `Conversation` | Aggregates messages and unread state for two Algorand addresses. |
| `DiscoveredKey` | Records a discovered encryption key, signature state, address, and source transaction. |
| `SendOptions` | Configures message sending, reply context, key publication, and confirmation behavior. |
| `SendResult` | Reports the transaction identifier and confirmed round of a successful send. |
| `PendingStatus` | Represents queued, sending, failed, and sent delivery states. |
| `PendingMessage` | Stores an offline outgoing message, retry metadata, and current pending status. |
| `MessageCache` | Defines asynchronous message persistence and lookup operations. |
| `InMemoryMessageCache` | Implements `MessageCache` with process-local storage. |
| `PublicKeyCache` | Caches discovered public keys in memory with TTL expiration. |
| `EncryptionKeyStorage` | Defines asynchronous private-key storage, retrieval, deletion, and existence checks. |
| `InMemoryKeyStorage` | Provides test-oriented process-local encryption-key storage. |
| `FileKeyStorage` | Persists encryption private keys in an at-rest encrypted filesystem format. |
| `AlgoChatError` | Provides the base exception for AlgoChat failures. |
| `InvalidPublicKeyError` | Reports an invalid public-key format or length. |
| `KeyDerivationError` | Reports failure to derive required cryptographic key material. |
| `InvalidSignatureError` | Reports malformed or unverifiable signature data. |
| `EncryptionError` | Reports failure to encrypt a standard message. |
| `DecryptionError` | Reports failure to authenticate or decrypt a standard message. |
| `InvalidEnvelopeError` | Reports an invalid standard envelope format. |
| `IndexerNotConfiguredError` | Reports an operation that requires an unconfigured indexer. |
| `PublicKeyNotFoundError` | Reports that no encryption public key was found for an address. |
| `UnverifiedKeyError` | Reports a discovered encryption key that failed Ed25519 verification. |
| `InvalidRecipientError` | Reports an invalid recipient address. |
| `TransactionError` | Reports failure to construct, submit, or confirm a transaction. |
| `InsufficientBalanceError` | Reports that an account cannot fund the required transaction. |
| `KeyNotFoundError` | Reports a missing key in configured storage. |
| `StorageError` | Reports a key or message storage operation failure. |
| `MessageNotFoundError` | Reports that a requested message is absent. |
| `MINIMUM_PAYMENT` | Defines the 1,000 microAlgo payment used to carry an AlgoChat note. |
| `QueueConfig` | Configures queue retries, retry delay, and processing behavior. |
| `SendQueue` | Manages asynchronous persistence and delivery of pending outgoing messages. |
| `AlgorandConfig` | Configures algod and indexer connection endpoints and credentials. |
| `TransactionInfo` | Records a submitted transaction identifier and confirmation round. |
| `NoteTransaction` | Models a blockchain payment transaction carrying note bytes. |
| `SuggestedParams` | Models fee, round, genesis, and flat-fee transaction parameters. |
| `AccountInfo` | Models an Algorand account balance and related node response data. |
| `AlgodClient` | Defines asynchronous node operations for parameters, accounts, submission, and confirmation. |
| `IndexerClient` | Defines asynchronous note-transaction lookup for an Algorand address. |
| `discover_encryption_key` | Finds and validates the latest published encryption key for an address. |
| `AlgoChatConfig` | Configures the high-level client, keys, transport clients, caches, and queue. |
| `AlgoChat` | Coordinates encrypted sending, receiving, discovery, storage, and queued delivery. |
| `PSK_VERSION` | Defines the PSK envelope version marker as `0x01`. |
| `PSK_PROTOCOL_ID` | Defines the PSK protocol discriminator as `0x02`. |
| `PSK_HEADER_SIZE` | Defines the PSK fixed header length as 130 bytes. |
| `PSK_TAG_SIZE` | Defines the PSK authentication-tag length as 16 bytes. |
| `PSK_ENCRYPTED_SENDER_KEY_SIZE` | Defines the encrypted sender-key field as 48 bytes. |
| `PSK_MAX_PAYLOAD_SIZE` | Caps a PSK envelope payload at 878 bytes. |
| `PSK_SESSION_SIZE` | Groups 100 ratchet positions into one derived PSK session. |
| `PSK_COUNTER_WINDOW` | Allows a 200-counter receive window for replay-safe out-of-order delivery. |
| `PSKEnvelope` | Stores PSK envelope counters, keys, nonce, ciphertext, and authentication tag. |
| `derive_session_psk` | Derives a session PSK from the initial PSK and session index. |
| `derive_position_psk` | Derives a position PSK from a session PSK and position. |
| `derive_psk_at_counter` | Derives the position-specific PSK for a global ratchet counter. |
| `derive_hybrid_symmetric_key` | Combines ECDH and PSK material into the message encryption key. |
| `derive_sender_key` | Derives the encrypted sender-key wrapping key for bidirectional decryption. |
| `encode_psk_envelope` | Serializes a `PSKEnvelope` into the PSK wire format. |
| `decode_psk_envelope` | Validates and parses PSK protocol bytes into a `PSKEnvelope`. |
| `is_psk_message` | Reports whether bytes have a structurally valid PSK envelope header. |
| `PSKEnvelopeError` | Reports PSK envelope encoding or decoding failure. |
| `PSKState` | Tracks send counters, received counters, and replay-window state for a PSK conversation. |
| `validate_counter` | Checks whether an incoming counter is new and inside the accepted receive window. |
| `record_receive` | Returns PSK state updated with a successfully received counter. |
| `advance_send_counter` | Returns the current send counter and PSK state advanced to the next position. |
| `create_psk_exchange_uri` | Encodes a pre-shared key and exchange metadata into an AlgoChat PSK URI. |
| `parse_psk_exchange_uri` | Validates and decodes an AlgoChat PSK exchange URI. |
| `encrypt_psk_message` | Encrypts authenticated content with the PSK v1.1 hybrid protocol. |
| `decrypt_psk_message` | Decrypts a PSK v1.1 envelope as recipient or originating sender. |
| `PSKEncryptionError` | Reports PSK-specific encryption failure. |
| `PSKDecryptionError` | Reports PSK-specific authentication or decryption failure. |
| `InvalidAddressError` | Reports an Algorand address with invalid encoding, length, or checksum. |
| `EnvelopeError` | Reports standard envelope encoding or decoding failure. |
| `x25519_ecdh` | Performs X25519 Diffie-Hellman key agreement. |
| `public_key_to_bytes` | Serializes an X25519 public key to its 32-byte raw representation. |
| `public_key_from_bytes` | Parses 32 raw bytes into an X25519 public key. |
| `PROTOCOL_VERSION` | Defines the standard envelope version marker as `0x01`. |
| `PROTOCOL_ID` | Defines the standard protocol discriminator as `0x01`. |
| `HEADER_SIZE` | Defines the standard fixed header length as 126 bytes. |
| `TAG_SIZE` | Defines the standard authentication-tag length as 16 bytes. |
| `ENCRYPTED_SENDER_KEY_SIZE` | Defines the encrypted sender-key field as 48 bytes. |
| `MAX_PAYLOAD_SIZE` | Caps a standard envelope payload at 882 bytes. |
| `NONCE_SIZE` | Defines ChaCha20-Poly1305 nonces as 12 bytes. |
| `PUBLIC_KEY_SIZE` | Defines serialized X25519 public keys as 32 bytes. |
| `KEY_DERIVATION_SALT` | Supplies the fixed `AlgoChat-v1-encryption` HKDF salt for seed derivation. |
| `KEY_DERIVATION_INFO` | Supplies the fixed `x25519-key` HKDF context for seed derivation. |
| `ENCRYPTION_INFO_PREFIX` | Domain-separates standard message encryption with `AlgoChatV1`. |
| `SENDER_KEY_INFO_PREFIX` | Domain-separates sender-key wrapping with `AlgoChatV1-SenderKey`. |

#### Standard Protocol and Models

The standard protocol surface covers deterministic and ephemeral X25519 keys, authenticated encryption, envelope encoding, key signatures, message models, conversations, replies, and delivery results.

#### Storage, Queue, Transport, and Client

The persistence and transport surface separates message caches, encrypted key storage, queued delivery, Algorand node/indexer abstractions, key discovery, and the high-level `AlgoChat` coordinator.

#### Errors

The explicit exception hierarchy keeps protocol, cryptographic, transport, address, balance, lookup, and persistence failures distinguishable.

#### PSK Protocol

The PSK v1.1 surface covers wire constants, hierarchical ratchet derivation, hybrid authenticated encryption, replay-safe receive state, and exchange URI handling.
