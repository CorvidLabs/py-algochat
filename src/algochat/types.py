"""Type definitions for AlgoChat."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class DecryptedContent:
    """Decrypted message content."""
    text: str
    reply_to_id: Optional[str] = None
    reply_to_preview: Optional[str] = None


# Protocol constants
PROTOCOL_VERSION = 0x01
PROTOCOL_ID = 0x01
HEADER_SIZE = 126
TAG_SIZE = 16
ENCRYPTED_SENDER_KEY_SIZE = 48  # 32-byte key + 16-byte tag
MAX_PAYLOAD_SIZE = 882
NONCE_SIZE = 12
PUBLIC_KEY_SIZE = 32

# Key derivation constants
KEY_DERIVATION_SALT = b"AlgoChat-v1-encryption"
KEY_DERIVATION_INFO = b"x25519-key"

# Encryption info prefixes
ENCRYPTION_INFO_PREFIX = b"AlgoChatV1"
SENDER_KEY_INFO_PREFIX = b"AlgoChatV1-SenderKey"
