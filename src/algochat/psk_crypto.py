"""PSK encryption and decryption for the v1.1 protocol."""

import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .psk_types import PSKEnvelope, PSK_MAX_PAYLOAD_SIZE
from .psk_ratchet import (
    derive_hybrid_symmetric_key,
    derive_sender_key,
)
from .keys import (
    generate_ephemeral_keypair,
    x25519_ecdh,
    public_key_to_bytes,
    public_key_from_bytes,
)
from .types import NONCE_SIZE


class PSKEncryptionError(Exception):
    """Raised when PSK encryption fails."""
    pass


class PSKDecryptionError(Exception):
    """Raised when PSK decryption fails."""
    pass


def encrypt_psk_message(
    plaintext: str,
    sender_private_key: X25519PrivateKey,
    sender_public_key: X25519PublicKey,
    recipient_public_key: X25519PublicKey,
    current_psk: bytes,
    ratchet_counter: int,
) -> PSKEnvelope:
    """Encrypt a message using the PSK v1.1 protocol.

    Args:
        plaintext: Message to encrypt.
        sender_private_key: Sender's X25519 private key.
        sender_public_key: Sender's X25519 public key.
        recipient_public_key: Recipient's X25519 public key.
        current_psk: The current ratcheted PSK (32 bytes).
        ratchet_counter: The ratchet counter for this message.

    Returns:
        PSKEnvelope containing the encrypted message.

    Raises:
        PSKEncryptionError: If encryption fails.
    """
    message_bytes = plaintext.encode("utf-8")

    if len(message_bytes) > PSK_MAX_PAYLOAD_SIZE:
        raise PSKEncryptionError(
            f"Message too large: {len(message_bytes)} bytes (max {PSK_MAX_PAYLOAD_SIZE})"
        )

    # Generate ephemeral key pair for this message
    ephemeral_private, ephemeral_public = generate_ephemeral_keypair()

    # Get raw bytes for all public keys
    sender_pub_bytes = public_key_to_bytes(sender_public_key)
    recipient_pub_bytes = public_key_to_bytes(recipient_public_key)
    ephemeral_pub_bytes = public_key_to_bytes(ephemeral_public)

    # ECDH with recipient
    shared_secret = x25519_ecdh(ephemeral_private, recipient_public_key)

    # Derive hybrid symmetric key (ECDH + PSK)
    symmetric_key = derive_hybrid_symmetric_key(
        shared_secret=shared_secret,
        current_psk=current_psk,
        ephemeral_public_key=ephemeral_pub_bytes,
        sender_public_key=sender_pub_bytes,
        recipient_public_key=recipient_pub_bytes,
    )

    # Generate random nonce
    nonce = os.urandom(NONCE_SIZE)

    # Encrypt message
    cipher = ChaCha20Poly1305(symmetric_key)
    ciphertext = cipher.encrypt(nonce, message_bytes, None)

    # Encrypt the symmetric key for sender (bidirectional decryption)
    sender_shared_secret = x25519_ecdh(ephemeral_private, sender_public_key)

    sender_encryption_key = derive_sender_key(
        sender_shared_secret=sender_shared_secret,
        current_psk=current_psk,
        ephemeral_public_key=ephemeral_pub_bytes,
        sender_public_key=sender_pub_bytes,
    )

    sender_cipher = ChaCha20Poly1305(sender_encryption_key)
    encrypted_sender_key = sender_cipher.encrypt(nonce, symmetric_key, None)

    return PSKEnvelope(
        ratchet_counter=ratchet_counter,
        sender_public_key=sender_pub_bytes,
        ephemeral_public_key=ephemeral_pub_bytes,
        nonce=nonce,
        encrypted_sender_key=encrypted_sender_key,
        ciphertext=ciphertext,
    )


def decrypt_psk_message(
    envelope: PSKEnvelope,
    recipient_private_key: X25519PrivateKey,
    recipient_public_key: X25519PublicKey,
    current_psk: bytes,
) -> str:
    """Decrypt a PSK v1.1 protocol message.

    Attempts decryption as recipient first, then as sender (bidirectional).

    Args:
        envelope: The PSK envelope to decrypt.
        recipient_private_key: Our X25519 private key.
        recipient_public_key: Our X25519 public key.
        current_psk: The current ratcheted PSK (32 bytes).

    Returns:
        Decrypted message text.

    Raises:
        PSKDecryptionError: If decryption fails.
    """
    my_pub_bytes = public_key_to_bytes(recipient_public_key)
    we_are_sender = my_pub_bytes == envelope.sender_public_key

    try:
        if we_are_sender:
            plaintext_bytes = _decrypt_psk_as_sender(
                envelope, recipient_private_key, my_pub_bytes, current_psk
            )
        else:
            plaintext_bytes = _decrypt_psk_as_recipient(
                envelope, recipient_private_key, my_pub_bytes, current_psk
            )

        return plaintext_bytes.decode("utf-8")
    except Exception as e:
        raise PSKDecryptionError(f"PSK decryption failed: {e}") from e


def _decrypt_psk_as_recipient(
    envelope: PSKEnvelope,
    recipient_private_key: X25519PrivateKey,
    recipient_pub_bytes: bytes,
    current_psk: bytes,
) -> bytes:
    """Decrypt a PSK message as the recipient."""
    ephemeral_public = public_key_from_bytes(envelope.ephemeral_public_key)

    shared_secret = x25519_ecdh(recipient_private_key, ephemeral_public)

    symmetric_key = derive_hybrid_symmetric_key(
        shared_secret=shared_secret,
        current_psk=current_psk,
        ephemeral_public_key=envelope.ephemeral_public_key,
        sender_public_key=envelope.sender_public_key,
        recipient_public_key=recipient_pub_bytes,
    )

    cipher = ChaCha20Poly1305(symmetric_key)
    return cipher.decrypt(envelope.nonce, envelope.ciphertext, None)


def _decrypt_psk_as_sender(
    envelope: PSKEnvelope,
    sender_private_key: X25519PrivateKey,
    sender_pub_bytes: bytes,
    current_psk: bytes,
) -> bytes:
    """Decrypt a PSK message as the sender (bidirectional)."""
    ephemeral_public = public_key_from_bytes(envelope.ephemeral_public_key)

    # First, recover the symmetric key
    sender_shared_secret = x25519_ecdh(sender_private_key, ephemeral_public)

    sender_decryption_key = derive_sender_key(
        sender_shared_secret=sender_shared_secret,
        current_psk=current_psk,
        ephemeral_public_key=envelope.ephemeral_public_key,
        sender_public_key=sender_pub_bytes,
    )

    sender_cipher = ChaCha20Poly1305(sender_decryption_key)
    symmetric_key = sender_cipher.decrypt(envelope.nonce, envelope.encrypted_sender_key, None)

    # Now decrypt the message
    cipher = ChaCha20Poly1305(symmetric_key)
    return cipher.decrypt(envelope.nonce, envelope.ciphertext, None)
