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
# Algorand accepts a 4096-byte note. 4097 is rejected.
MAX_NOTE_SIZE = 4096
# First 1024 note bytes are included in one minimum fee.
_NOTE_FEE_INCLUDED_BYTES = 1024
# Header stays 126 and the Poly1305 tag stays 16, so plaintext max is 3954.
MAX_PAYLOAD_SIZE = MAX_NOTE_SIZE - HEADER_SIZE - TAG_SIZE
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


def payment_fee(note_size: int, min_fee: int) -> int:
    """Return the microAlgo fee for a payment that carries a note.

    The first 1024 bytes cost one minimum fee. Each byte past 1024 adds one
    ten-thousandth of ``min_fee``, rounded up once. This library has no Falcon
    signer, so the scheme component is one minimum fee and the note surcharge
    is added on top.

    Args:
        note_size: Encoded note length in bytes. Must be from 0 through
            ``MAX_NOTE_SIZE``.
        min_fee: Network minimum fee in microAlgos.

    Returns:
        Fee in microAlgos.

    Raises:
        ValueError: If the note is larger than ``MAX_NOTE_SIZE`` or ``min_fee``
            is negative.
    """
    if note_size < 0 or note_size > MAX_NOTE_SIZE:
        raise ValueError(f"Note is {note_size} bytes; the maximum is {MAX_NOTE_SIZE}")
    if min_fee < 0:
        raise ValueError(f"min_fee must be non-negative, got {min_fee}")
    over = max(0, note_size - _NOTE_FEE_INCLUDED_BYTES)
    surcharge = (over * min_fee + 9999) // 10000
    return min_fee + surcharge


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


class UnverifiedKeyError(AlgoChatError):
    """An encryption key failed Ed25519 verification and may not be trusted."""
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


class PSKEncryptionError(EncryptionError):
    """PSK encryption failed."""
    pass


class PSKDecryptionError(DecryptionError):
    """PSK decryption failed."""
    pass
