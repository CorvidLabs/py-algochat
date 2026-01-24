"""
Signature verification for AlgoChat encryption keys.

This module provides functions to sign encryption public keys with an
Algorand account's Ed25519 key, and verify those signatures. This prevents
key substitution attacks by proving key ownership.
"""

import hashlib
from typing import Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


# Size constants
ED25519_SIGNATURE_SIZE = 64
ED25519_PUBLIC_KEY_SIZE = 32
X25519_PUBLIC_KEY_SIZE = 32


class SignatureError(Exception):
    """Error raised when signature operations fail."""
    pass


def sign_encryption_key(
    encryption_public_key: bytes,
    signing_key: Ed25519PrivateKey,
) -> bytes:
    """
    Sign an encryption public key with an Ed25519 signing key.

    This creates a cryptographic proof that the encryption key belongs to
    the holder of the Ed25519 private key (Algorand account).

    Args:
        encryption_public_key: The X25519 public key to sign (32 bytes)
        signing_key: The Ed25519 signing key

    Returns:
        The Ed25519 signature (64 bytes)

    Raises:
        SignatureError: If the key length is invalid
    """
    if len(encryption_public_key) != X25519_PUBLIC_KEY_SIZE:
        raise SignatureError(
            f"Encryption public key must be {X25519_PUBLIC_KEY_SIZE} bytes, "
            f"got {len(encryption_public_key)}"
        )

    return signing_key.sign(encryption_public_key)


def sign_encryption_key_bytes(
    encryption_public_key: bytes,
    signing_key_bytes: bytes,
) -> bytes:
    """
    Sign an encryption public key using raw Ed25519 private key bytes.

    Args:
        encryption_public_key: The X25519 public key to sign (32 bytes)
        signing_key_bytes: The Ed25519 private key bytes (32 bytes)

    Returns:
        The Ed25519 signature (64 bytes)

    Raises:
        SignatureError: If the key lengths are invalid
    """
    if len(signing_key_bytes) != ED25519_PUBLIC_KEY_SIZE:
        raise SignatureError(
            f"Signing key must be {ED25519_PUBLIC_KEY_SIZE} bytes, "
            f"got {len(signing_key_bytes)}"
        )

    signing_key = Ed25519PrivateKey.from_private_bytes(signing_key_bytes)
    return sign_encryption_key(encryption_public_key, signing_key)


def verify_encryption_key(
    encryption_public_key: bytes,
    verifying_key: Ed25519PublicKey,
    signature: bytes,
) -> bool:
    """
    Verify that an encryption public key was signed by an Ed25519 key.

    This checks that the signature over the X25519 encryption key was
    created by the Ed25519 private key corresponding to the given public key.

    Args:
        encryption_public_key: The X25519 public key (32 bytes)
        verifying_key: The Ed25519 public key
        signature: The Ed25519 signature to verify (64 bytes)

    Returns:
        True if the signature is valid, False otherwise

    Raises:
        SignatureError: If the key or signature lengths are invalid
    """
    if len(encryption_public_key) != X25519_PUBLIC_KEY_SIZE:
        raise SignatureError(
            f"Encryption public key must be {X25519_PUBLIC_KEY_SIZE} bytes, "
            f"got {len(encryption_public_key)}"
        )

    if len(signature) != ED25519_SIGNATURE_SIZE:
        raise SignatureError(
            f"Signature must be {ED25519_SIGNATURE_SIZE} bytes, "
            f"got {len(signature)}"
        )

    try:
        verifying_key.verify(signature, encryption_public_key)
        return True
    except InvalidSignature:
        return False


def verify_encryption_key_bytes(
    encryption_public_key: bytes,
    ed25519_public_key: bytes,
    signature: bytes,
) -> bool:
    """
    Verify an encryption key using raw Ed25519 public key bytes.

    Args:
        encryption_public_key: The X25519 public key (32 bytes)
        ed25519_public_key: The Ed25519 public key bytes (32 bytes, e.g., Algorand address bytes)
        signature: The Ed25519 signature (64 bytes)

    Returns:
        True if the signature is valid, False otherwise

    Raises:
        SignatureError: If any key or signature lengths are invalid
    """
    if len(ed25519_public_key) != ED25519_PUBLIC_KEY_SIZE:
        raise SignatureError(
            f"Ed25519 public key must be {ED25519_PUBLIC_KEY_SIZE} bytes, "
            f"got {len(ed25519_public_key)}"
        )

    try:
        verifying_key = Ed25519PublicKey.from_public_bytes(ed25519_public_key)
    except Exception as e:
        raise SignatureError(f"Invalid Ed25519 public key: {e}")

    return verify_encryption_key(encryption_public_key, verifying_key, signature)


def get_public_key(private_key: Union[Ed25519PrivateKey, bytes]) -> bytes:
    """
    Get the Ed25519 public key from a private key.

    Args:
        private_key: The Ed25519 private key (object or 32 bytes)

    Returns:
        The Ed25519 public key bytes (32 bytes)
    """
    if isinstance(private_key, bytes):
        private_key = Ed25519PrivateKey.from_private_bytes(private_key)

    return private_key.public_key().public_bytes_raw()


def fingerprint(public_key: bytes) -> str:
    """
    Generate a human-readable fingerprint for an encryption public key.

    The fingerprint is a truncated SHA-256 hash formatted for easy comparison.

    Args:
        public_key: The encryption public key (32 bytes)

    Returns:
        A fingerprint string like "A7B3C9D1 E5F28A4B"
    """
    hash_bytes = hashlib.sha256(public_key).digest()

    # Take first 8 bytes and format as hex groups
    hex_bytes = [f"{b:02X}" for b in hash_bytes[:8]]

    # Group into pairs of bytes (4 chars each), space separated
    groups = [hex_bytes[i] + hex_bytes[i + 1] for i in range(0, 8, 2)]

    return " ".join(groups)
