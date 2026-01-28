"""
AlgoChat - Encrypted messaging on Algorand

Python implementation of the AlgoChat protocol using X25519 + ChaCha20-Poly1305.
"""

from .keys import derive_keys_from_seed, generate_ephemeral_keypair
from .crypto import encrypt_message, decrypt_message
from .envelope import encode_envelope, decode_envelope, is_chat_message, ChatEnvelope
from .types import (
    DecryptedContent,
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
from .psk_types import (
    PSK_VERSION,
    PSK_PROTOCOL_ID,
    PSK_HEADER_SIZE,
    PSK_TAG_SIZE,
    PSK_ENCRYPTED_SENDER_KEY_SIZE,
    PSK_MAX_PAYLOAD_SIZE,
    PSK_SESSION_SIZE,
    PSK_COUNTER_WINDOW,
    PSKEnvelope,
)
from .psk_ratchet import (
    derive_session_psk,
    derive_position_psk,
    derive_psk_at_counter,
    derive_hybrid_symmetric_key,
    derive_sender_key,
)
from .psk_envelope import (
    encode_psk_envelope,
    decode_psk_envelope,
    is_psk_message,
    PSKEnvelopeError,
)
from .psk_state import (
    PSKState,
    validate_counter,
    record_receive,
    advance_send_counter,
)
from .psk_exchange import (
    create_psk_exchange_uri,
    parse_psk_exchange_uri,
)
from .psk_crypto import (
    encrypt_psk_message,
    decrypt_psk_message,
    PSKEncryptionError,
    PSKDecryptionError,
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
    # PSK Types
    "PSK_VERSION",
    "PSK_PROTOCOL_ID",
    "PSK_HEADER_SIZE",
    "PSK_TAG_SIZE",
    "PSK_ENCRYPTED_SENDER_KEY_SIZE",
    "PSK_MAX_PAYLOAD_SIZE",
    "PSK_SESSION_SIZE",
    "PSK_COUNTER_WINDOW",
    "PSKEnvelope",
    # PSK Ratchet
    "derive_session_psk",
    "derive_position_psk",
    "derive_psk_at_counter",
    "derive_hybrid_symmetric_key",
    "derive_sender_key",
    # PSK Envelope
    "encode_psk_envelope",
    "decode_psk_envelope",
    "is_psk_message",
    "PSKEnvelopeError",
    # PSK State
    "PSKState",
    "validate_counter",
    "record_receive",
    "advance_send_counter",
    # PSK Exchange
    "create_psk_exchange_uri",
    "parse_psk_exchange_uri",
    # PSK Crypto
    "encrypt_psk_message",
    "decrypt_psk_message",
    "PSKEncryptionError",
    "PSKDecryptionError",
]
