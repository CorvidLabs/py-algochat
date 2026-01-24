"""Encryption and decryption for AlgoChat messages."""

import os
import json
from typing import Optional

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .types import (
    DecryptedContent,
    ENCRYPTION_INFO_PREFIX,
    SENDER_KEY_INFO_PREFIX,
    MAX_PAYLOAD_SIZE,
    NONCE_SIZE,
)
from .keys import generate_ephemeral_keypair, x25519_ecdh, public_key_to_bytes, public_key_from_bytes
from .envelope import ChatEnvelope


class EncryptionError(Exception):
    """Raised when encryption fails."""
    pass


class DecryptionError(Exception):
    """Raised when decryption fails."""
    pass


def encrypt_message(
    plaintext: str,
    sender_private_key: X25519PrivateKey,
    sender_public_key: X25519PublicKey,
    recipient_public_key: X25519PublicKey,
) -> ChatEnvelope:
    """
    Encrypt a message for a recipient.

    Args:
        plaintext: Message to encrypt
        sender_private_key: Sender's X25519 private key (unused but kept for API compatibility)
        sender_public_key: Sender's X25519 public key
        recipient_public_key: Recipient's X25519 public key

    Returns:
        ChatEnvelope containing the encrypted message
    """
    message_bytes = plaintext.encode("utf-8")

    if len(message_bytes) > MAX_PAYLOAD_SIZE:
        raise EncryptionError(f"Message too large: {len(message_bytes)} bytes (max {MAX_PAYLOAD_SIZE})")

    # Generate ephemeral key pair for this message
    ephemeral_private, ephemeral_public = generate_ephemeral_keypair()

    # Derive symmetric key for message encryption
    sender_pub_bytes = public_key_to_bytes(sender_public_key)
    recipient_pub_bytes = public_key_to_bytes(recipient_public_key)
    ephemeral_pub_bytes = public_key_to_bytes(ephemeral_public)

    shared_secret = x25519_ecdh(ephemeral_private, recipient_public_key)
    info = ENCRYPTION_INFO_PREFIX + sender_pub_bytes + recipient_pub_bytes

    hkdf = HKDF(algorithm=SHA256(), length=32, salt=ephemeral_pub_bytes, info=info)
    symmetric_key = hkdf.derive(shared_secret)

    # Generate random nonce
    nonce = os.urandom(NONCE_SIZE)

    # Encrypt message
    cipher = ChaCha20Poly1305(symmetric_key)
    ciphertext = cipher.encrypt(nonce, message_bytes, None)

    # Encrypt the symmetric key for sender (bidirectional decryption)
    sender_shared_secret = x25519_ecdh(ephemeral_private, sender_public_key)
    sender_info = SENDER_KEY_INFO_PREFIX + sender_pub_bytes

    sender_hkdf = HKDF(algorithm=SHA256(), length=32, salt=ephemeral_pub_bytes, info=sender_info)
    sender_encryption_key = sender_hkdf.derive(sender_shared_secret)

    sender_cipher = ChaCha20Poly1305(sender_encryption_key)
    encrypted_sender_key = sender_cipher.encrypt(nonce, symmetric_key, None)

    return ChatEnvelope(
        version=0x01,
        protocol_id=0x01,
        sender_public_key=sender_pub_bytes,
        ephemeral_public_key=ephemeral_pub_bytes,
        nonce=nonce,
        encrypted_sender_key=encrypted_sender_key,
        ciphertext=ciphertext,
    )


def decrypt_message(
    envelope: ChatEnvelope,
    my_private_key: X25519PrivateKey,
    my_public_key: X25519PublicKey,
) -> Optional[DecryptedContent]:
    """
    Decrypt a message from an envelope.

    Args:
        envelope: The encrypted envelope
        my_private_key: Our X25519 private key
        my_public_key: Our X25519 public key

    Returns:
        DecryptedContent if successful, None if it's a key-publish message
    """
    my_pub_bytes = public_key_to_bytes(my_public_key)
    we_are_sender = my_pub_bytes == envelope.sender_public_key

    if we_are_sender:
        plaintext = _decrypt_as_sender(envelope, my_private_key, my_pub_bytes)
    else:
        plaintext = _decrypt_as_recipient(envelope, my_private_key, my_pub_bytes)

    # Check for key-publish payload
    if _is_key_publish_payload(plaintext):
        return None

    return _parse_message_payload(plaintext)


def _decrypt_as_recipient(
    envelope: ChatEnvelope,
    recipient_private_key: X25519PrivateKey,
    recipient_pub_bytes: bytes,
) -> bytes:
    """Decrypt message as the recipient."""
    ephemeral_public = public_key_from_bytes(envelope.ephemeral_public_key)

    shared_secret = x25519_ecdh(recipient_private_key, ephemeral_public)
    info = ENCRYPTION_INFO_PREFIX + envelope.sender_public_key + recipient_pub_bytes

    hkdf = HKDF(algorithm=SHA256(), length=32, salt=envelope.ephemeral_public_key, info=info)
    symmetric_key = hkdf.derive(shared_secret)

    cipher = ChaCha20Poly1305(symmetric_key)
    return cipher.decrypt(envelope.nonce, envelope.ciphertext, None)


def _decrypt_as_sender(
    envelope: ChatEnvelope,
    sender_private_key: X25519PrivateKey,
    sender_pub_bytes: bytes,
) -> bytes:
    """Decrypt message as the sender (bidirectional)."""
    ephemeral_public = public_key_from_bytes(envelope.ephemeral_public_key)

    # First, recover the symmetric key
    shared_secret = x25519_ecdh(sender_private_key, ephemeral_public)
    sender_info = SENDER_KEY_INFO_PREFIX + sender_pub_bytes

    sender_hkdf = HKDF(algorithm=SHA256(), length=32, salt=envelope.ephemeral_public_key, info=sender_info)
    sender_decryption_key = sender_hkdf.derive(shared_secret)

    sender_cipher = ChaCha20Poly1305(sender_decryption_key)
    symmetric_key = sender_cipher.decrypt(envelope.nonce, envelope.encrypted_sender_key, None)

    # Now decrypt the message
    cipher = ChaCha20Poly1305(symmetric_key)
    return cipher.decrypt(envelope.nonce, envelope.ciphertext, None)


def _is_key_publish_payload(data: bytes) -> bool:
    """Check if payload is a key-publish message."""
    if not data or data[0:1] != b"{":
        return False
    try:
        payload = json.loads(data.decode("utf-8"))
        return payload.get("type") == "key-publish"
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False


def _parse_message_payload(data: bytes) -> DecryptedContent:
    """Parse decrypted payload into content."""
    text = data.decode("utf-8")

    # Try to parse as JSON (for structured messages with reply context)
    if text.startswith("{"):
        try:
            payload = json.loads(text)
            if isinstance(payload.get("text"), str):
                reply_to = payload.get("replyTo", {})
                return DecryptedContent(
                    text=payload["text"],
                    reply_to_id=reply_to.get("txid"),
                    reply_to_preview=reply_to.get("preview"),
                )
        except json.JSONDecodeError:
            pass

    return DecryptedContent(text=text)
