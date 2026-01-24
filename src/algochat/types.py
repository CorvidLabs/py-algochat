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

# Signature constants
SIGNATURE_SIZE = 64

# Transaction constants
MINIMUM_PAYMENT = 1000


# Exception types
class AlgoChatError(Exception):
    """Base exception for AlgoChat errors."""
    pass


class InvalidPublicKeyError(AlgoChatError):
    """Invalid public key format or length."""
    pass


class KeyDerivationError(AlgoChatError):
    """Key derivation failed."""
    pass


class InvalidSignatureError(AlgoChatError):
    """Invalid signature format or verification failed."""
    pass


class EncryptionError(AlgoChatError):
    """Encryption failed."""
    pass


class DecryptionError(AlgoChatError):
    """Decryption failed."""
    pass


class InvalidEnvelopeError(AlgoChatError):
    """Invalid envelope format."""
    pass


class IndexerNotConfiguredError(AlgoChatError):
    """Indexer not configured."""
    pass


class PublicKeyNotFoundError(AlgoChatError):
    """Public key not found for address."""
    pass


class InvalidRecipientError(AlgoChatError):
    """Invalid recipient address."""
    pass


class TransactionError(AlgoChatError):
    """Transaction failed."""
    pass


class InsufficientBalanceError(AlgoChatError):
    """Insufficient balance."""
    pass


class KeyNotFoundError(AlgoChatError):
    """Key not found in storage."""
    pass


class StorageError(AlgoChatError):
    """Storage operation failed."""
    pass


class MessageNotFoundError(AlgoChatError):
    """Message not found."""
    pass
