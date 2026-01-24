"""
AlgoChat - Encrypted messaging on Algorand

Python implementation of the AlgoChat protocol using X25519 + ChaCha20-Poly1305.
"""

from .keys import derive_keys_from_seed, generate_ephemeral_keypair
from .crypto import encrypt_message, decrypt_message
from .envelope import encode_envelope, decode_envelope, is_chat_message, ChatEnvelope
from .types import DecryptedContent
from .account import ChatAccount
from .client import (
    AlgoChatClient,
    AlgoChatError,
    PublicKeyNotFoundError,
    InsufficientBalanceError,
    MessageTooLargeError,
)
from .signature import (
    sign_encryption_key,
    sign_encryption_key_bytes,
    verify_encryption_key,
    verify_encryption_key_bytes,
    get_public_key,
    fingerprint,
    SignatureError,
    ED25519_SIGNATURE_SIZE,
    ED25519_PUBLIC_KEY_SIZE,
    X25519_PUBLIC_KEY_SIZE,
)
from .models import (
    MessageDirection,
    ReplyContext,
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
    KeyNotFoundError,
    FileKeyStorage,
    PasswordRequiredError,
    DecryptionFailedError,
    InvalidKeyDataError,
)
from .queue import (
    SendQueue,
    QueueConfig,
    QueueFullError,
    MessageNotFoundError,
)
from .blockchain import (
    AlgorandConfig,
    TransactionInfo,
    NoteTransaction,
    SuggestedParams,
    AccountInfo,
    AlgodClient,
    IndexerClient,
    parse_key_announcement,
    discover_encryption_key,
)

__version__ = "0.1.0"

__all__ = [
    # Account
    "ChatAccount",
    # Client
    "AlgoChatClient",
    "AlgoChatError",
    "PublicKeyNotFoundError",
    "InsufficientBalanceError",
    "MessageTooLargeError",
    # Crypto
    "derive_keys_from_seed",
    "generate_ephemeral_keypair",
    "encrypt_message",
    "decrypt_message",
    "encode_envelope",
    "decode_envelope",
    "is_chat_message",
    "ChatEnvelope",
    "DecryptedContent",
    # Signature
    "sign_encryption_key",
    "sign_encryption_key_bytes",
    "verify_encryption_key",
    "verify_encryption_key_bytes",
    "get_public_key",
    "fingerprint",
    "SignatureError",
    "ED25519_SIGNATURE_SIZE",
    "ED25519_PUBLIC_KEY_SIZE",
    "X25519_PUBLIC_KEY_SIZE",
    # Models
    "MessageDirection",
    "ReplyContext",
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
    "KeyNotFoundError",
    "FileKeyStorage",
    "PasswordRequiredError",
    "DecryptionFailedError",
    "InvalidKeyDataError",
    # Queue
    "SendQueue",
    "QueueConfig",
    "QueueFullError",
    "MessageNotFoundError",
    # Blockchain
    "AlgorandConfig",
    "TransactionInfo",
    "NoteTransaction",
    "SuggestedParams",
    "AccountInfo",
    "AlgodClient",
    "IndexerClient",
    "parse_key_announcement",
    "discover_encryption_key",
]
