"""Signature verification for AlgoChat encryption keys.

This module provides functions to sign encryption public keys with an
Algorand account's Ed25519 key, and verify those signatures. This prevents
key substitution attacks by proving key ownership.
"""

import hashlib
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Size of an Ed25519 signature (64 bytes)
SIGNATURE_SIZE = 64


def sign_encryption_key(
    encryption_public_key: bytes,
    signing_key: Ed25519PrivateKey,
) -> bytes:
    """Signs an encryption public key with an Ed25519 signing key.

    This creates a cryptographic proof that the encryption key belongs to
    the holder of the Ed25519 private key (Algorand account).

    Args:
        encryption_public_key: The X25519 public key to sign (32 bytes)
        signing_key: The Ed25519 signing key (from Algorand account)

    Returns:
        The Ed25519 signature (64 bytes)

    Raises:
        ValueError: If encryption_public_key is not 32 bytes
    """
    if len(encryption_public_key) != 32:
        raise ValueError(
            f"Encryption public key must be 32 bytes, got {len(encryption_public_key)}"
        )

    return signing_key.sign(encryption_public_key)


def verify_encryption_key(
    encryption_public_key: bytes,
    verifying_key: Ed25519PublicKey,
    signature: bytes,
) -> bool:
    """Verifies that an encryption public key was signed by an Ed25519 key.

    Args:
        encryption_public_key: The X25519 public key (32 bytes)
        verifying_key: The Ed25519 public key (from Algorand address)
        signature: The Ed25519 signature to verify (64 bytes)

    Returns:
        True if the signature is valid, False otherwise

    Raises:
        ValueError: If encryption_public_key is not 32 bytes or signature is not 64 bytes
    """
    if len(encryption_public_key) != 32:
        raise ValueError(
            f"Encryption public key must be 32 bytes, got {len(encryption_public_key)}"
        )

    if len(signature) != SIGNATURE_SIZE:
        raise ValueError(
            f"Signature must be {SIGNATURE_SIZE} bytes, got {len(signature)}"
        )

    try:
        verifying_key.verify(signature, encryption_public_key)
        return True
    except Exception:
        return False


def verify_encryption_key_bytes(
    encryption_public_key: bytes,
    ed25519_public_key: bytes,
    signature: bytes,
) -> bool:
    """Verifies an encryption key using raw Ed25519 public key bytes.

    Args:
        encryption_public_key: The X25519 public key (32 bytes)
        ed25519_public_key: The Ed25519 public key bytes (32 bytes)
        signature: The Ed25519 signature (64 bytes)

    Returns:
        True if the signature is valid, False otherwise

    Raises:
        ValueError: If any input has invalid length
    """
    if len(ed25519_public_key) != 32:
        raise ValueError(
            f"Ed25519 public key must be 32 bytes, got {len(ed25519_public_key)}"
        )

    verifying_key = Ed25519PublicKey.from_public_bytes(ed25519_public_key)
    return verify_encryption_key(encryption_public_key, verifying_key, signature)


def fingerprint(public_key: bytes) -> str:
    """Generates a human-readable fingerprint for an encryption public key.

    The fingerprint is a truncated SHA-256 hash formatted for easy comparison.

    Args:
        public_key: The encryption public key (any length, typically 32 bytes)

    Returns:
        A fingerprint string like "A7B3 C9D1 E5F2 8A4B"
    """
    hash_bytes = hashlib.sha256(public_key).digest()[:8]
    hex_chars = hash_bytes.hex().upper()
    # Group into pairs of 4 characters
    groups = [hex_chars[i : i + 4] for i in range(0, len(hex_chars), 4)]
    return " ".join(groups)
