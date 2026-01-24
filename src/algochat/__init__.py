"""
AlgoChat - Encrypted messaging on Algorand

Python implementation of the AlgoChat protocol using X25519 + ChaCha20-Poly1305.
"""

from .keys import derive_keys_from_seed, generate_ephemeral_keypair
from .crypto import encrypt_message, decrypt_message
from .envelope import encode_envelope, decode_envelope, is_chat_message, ChatEnvelope
from .types import DecryptedContent

__version__ = "0.1.0"

__all__ = [
    "derive_keys_from_seed",
    "generate_ephemeral_keypair",
    "encrypt_message",
    "decrypt_message",
    "encode_envelope",
    "decode_envelope",
    "is_chat_message",
    "ChatEnvelope",
    "DecryptedContent",
]
