"""Key derivation and management for AlgoChat."""

import os
from typing import Tuple

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .types import KEY_DERIVATION_SALT, KEY_DERIVATION_INFO


def derive_keys_from_seed(seed: bytes) -> Tuple[X25519PrivateKey, X25519PublicKey]:
    """
    Derive X25519 key pair from a 32-byte seed using HKDF-SHA256.

    Args:
        seed: 32-byte seed (e.g., from Algorand account secret key)

    Returns:
        Tuple of (private_key, public_key)
    """
    if len(seed) != 32:
        raise ValueError(f"Seed must be 32 bytes, got {len(seed)}")

    # Derive key material using HKDF
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=KEY_DERIVATION_SALT,
        info=KEY_DERIVATION_INFO,
    )
    derived_key = hkdf.derive(seed)

    # Create X25519 key pair
    private_key = X25519PrivateKey.from_private_bytes(derived_key)
    public_key = private_key.public_key()

    return private_key, public_key


def generate_ephemeral_keypair() -> Tuple[X25519PrivateKey, X25519PublicKey]:
    """
    Generate a random ephemeral X25519 key pair for message encryption.

    Returns:
        Tuple of (private_key, public_key)
    """
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def x25519_ecdh(private_key: X25519PrivateKey, public_key: X25519PublicKey) -> bytes:
    """
    Perform X25519 ECDH key exchange.

    Args:
        private_key: Our private key
        public_key: Their public key

    Returns:
        32-byte shared secret
    """
    return private_key.exchange(public_key)


def public_key_to_bytes(public_key: X25519PublicKey) -> bytes:
    """Convert X25519 public key to raw bytes."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def public_key_from_bytes(data: bytes) -> X25519PublicKey:
    """Create X25519 public key from raw bytes."""
    return X25519PublicKey.from_public_bytes(data)
