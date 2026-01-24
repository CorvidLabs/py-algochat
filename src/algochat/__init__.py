"""
AlgoChat - Encrypted messaging on Algorand

Python implementation of the AlgoChat protocol using X25519 + ChaCha20-Poly1305.
"""

from .keys import derive_keys_from_seed, generate_ephemeral_keypair
from .crypto import encrypt_message, decrypt_message
from .envelope import encode_envelope, decode_envelope, is_chat_message, ChatEnvelope
from .types import (
    DecryptedContent,
    SIGNATURE_SIZE as _SIG_SIZE,  # Already exported from signature module
    MINIMUM_PAYMENT,
    AlgoChatError,
    InvalidPublicKeyError,
    KeyDerivationError,
    InvalidSignatureError,
    EncryptionError,
    DecryptionError,
    InvalidEnvelopeError,
    IndexerNotConfiguredError,
    PublicKeyNotFoundError,
    InvalidRecipientError,
    TransactionError,
    InsufficientBalanceError,
    KeyNotFoundError,
    StorageError,
    MessageNotFoundError,
)
from .signature import (
    sign_encryption_key,
    verify_encryption_key,
    verify_encryption_key_bytes,
    fingerprint,
    SIGNATURE_SIZE,
)
from .models import (
    ReplyContext,
    MessageDirection,
    Message,
    Conversation,
    DiscoveredKey,
    SendOptions,
    SendResult,
    PendingStatus,
    PendingMessage,
)
from .storage import (
    MessageCache,
    InMemoryMessageCache,
    PublicKeyCache,
    EncryptionKeyStorage,
    InMemoryKeyStorage,
)
from .queue import (
    QueueConfig,
    SendQueue,
)
from .blockchain import (
    AlgorandConfig,
    TransactionInfo,
    NoteTransaction,
    SuggestedParams,
    AccountInfo,
    AlgodClient,
    IndexerClient,
    discover_encryption_key,
)
from .client import (
    AlgoChatConfig,
    AlgoChat,
)

__version__ = "0.1.0"

__all__ = [
    # Keys
    "derive_keys_from_seed",
    "generate_ephemeral_keypair",
    # Crypto
    "encrypt_message",
    "decrypt_message",
    # Envelope
    "encode_envelope",
    "decode_envelope",
    "is_chat_message",
    "ChatEnvelope",
    # Types
    "DecryptedContent",
    # Signature
    "sign_encryption_key",
    "verify_encryption_key",
    "verify_encryption_key_bytes",
    "fingerprint",
    "SIGNATURE_SIZE",
    # Models
    "ReplyContext",
    "MessageDirection",
    "Message",
    "Conversation",
    "DiscoveredKey",
    "SendOptions",
    "SendResult",
    "PendingStatus",
    "PendingMessage",
    # Storage
    "MessageCache",
    "InMemoryMessageCache",
    "PublicKeyCache",
    "EncryptionKeyStorage",
    "InMemoryKeyStorage",
    # Errors
    "AlgoChatError",
    "InvalidPublicKeyError",
    "KeyDerivationError",
    "InvalidSignatureError",
    "EncryptionError",
    "DecryptionError",
    "InvalidEnvelopeError",
    "IndexerNotConfiguredError",
    "PublicKeyNotFoundError",
    "InvalidRecipientError",
    "TransactionError",
    "InsufficientBalanceError",
    "KeyNotFoundError",
    "StorageError",
    "MessageNotFoundError",
    # Constants
    "MINIMUM_PAYMENT",
    # Queue
    "QueueConfig",
    "SendQueue",
    # Blockchain
    "AlgorandConfig",
    "TransactionInfo",
    "NoteTransaction",
    "SuggestedParams",
    "AccountInfo",
    "AlgodClient",
    "IndexerClient",
    "discover_encryption_key",
    # Client
    "AlgoChatConfig",
    "AlgoChat",
]
