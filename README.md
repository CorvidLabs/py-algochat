# py-algochat

Python implementation of the AlgoChat protocol for encrypted messaging on Algorand.

## Installation

```bash
pip install py-algochat
```

## Usage

```python
from algochat import derive_keys_from_seed, encrypt_message, decrypt_message
from algochat import encode_envelope, decode_envelope

# Derive keys from a 32-byte seed (e.g., from Algorand account)
sender_private, sender_public = derive_keys_from_seed(seed_bytes)
recipient_private, recipient_public = derive_keys_from_seed(recipient_seed)

# Encrypt a message
envelope = encrypt_message(
    "Hello, World!",
    sender_private,
    sender_public,
    recipient_public,
)

# Encode for transmission
encoded = encode_envelope(envelope)

# Decode received message
decoded = decode_envelope(encoded)

# Decrypt as recipient
result = decrypt_message(decoded, recipient_private, recipient_public)
print(result.text)  # "Hello, World!"
```

## Protocol

AlgoChat uses:
- **X25519** for key agreement
- **ChaCha20-Poly1305** for authenticated encryption
- **HKDF-SHA256** for key derivation

The protocol supports bidirectional decryption, allowing senders to decrypt their own messages.

## Cross-Implementation Compatibility

This implementation is fully compatible with:
- [swift-algochat](https://github.com/CorvidLabs/swift-algochat) (Swift)
- [ts-algochat](https://github.com/CorvidLabs/ts-algochat) (TypeScript)

## License

MIT
