"""Tests for signature verification of encryption keys.

Covers:
- Sign/verify round-trip
- Wrong key fails verification
- Wrong message (different encryption key) fails verification
- Corrupted signature fails verification
- Fingerprint format and determinism
- Invalid input lengths
- verify_encryption_key_bytes convenience function
"""

import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from algochat.signature import (
    SIGNATURE_SIZE,
    fingerprint,
    sign_encryption_key,
    verify_encryption_key,
    verify_encryption_key_bytes,
)


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a random Ed25519 key pair for testing."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def random_encryption_key() -> bytes:
    """Generate a random 32-byte encryption key for testing."""
    return os.urandom(32)


# =============================================================================
# Sign / Verify Round-Trip Tests
# =============================================================================


class TestSignVerifyRoundTrip:
    """Test that signing and verifying produces correct results."""

    def test_sign_and_verify_succeeds(self) -> None:
        """Sign an encryption key and verify the signature."""
        signing_key, verifying_key = generate_ed25519_keypair()
        encryption_key = random_encryption_key()

        signature = sign_encryption_key(encryption_key, signing_key)

        assert len(signature) == SIGNATURE_SIZE
        assert verify_encryption_key(encryption_key, verifying_key, signature)

    def test_sign_is_deterministic(self) -> None:
        """Ed25519 signing is deterministic; same inputs produce same signature."""
        signing_key, _ = generate_ed25519_keypair()
        encryption_key = random_encryption_key()

        sig1 = sign_encryption_key(encryption_key, signing_key)
        sig2 = sign_encryption_key(encryption_key, signing_key)

        assert sig1 == sig2

    def test_different_encryption_keys_produce_different_signatures(self) -> None:
        """Signing different encryption keys produces different signatures."""
        signing_key, _ = generate_ed25519_keypair()
        enc_key1 = random_encryption_key()
        enc_key2 = random_encryption_key()

        sig1 = sign_encryption_key(enc_key1, signing_key)
        sig2 = sign_encryption_key(enc_key2, signing_key)

        assert sig1 != sig2

    def test_sign_and_verify_multiple_times(self) -> None:
        """Multiple sign/verify round-trips all succeed."""
        signing_key, verifying_key = generate_ed25519_keypair()

        for _ in range(10):
            encryption_key = random_encryption_key()
            signature = sign_encryption_key(encryption_key, signing_key)
            assert verify_encryption_key(encryption_key, verifying_key, signature)


# =============================================================================
# Wrong Key Tests
# =============================================================================


class TestWrongKeyFails:
    """Test that verification fails when the wrong key is used."""

    def test_wrong_verifying_key_fails(self) -> None:
        """Signature verified with a different Ed25519 key returns False."""
        signing_key, _ = generate_ed25519_keypair()
        _, wrong_verifying_key = generate_ed25519_keypair()
        encryption_key = random_encryption_key()

        signature = sign_encryption_key(encryption_key, signing_key)

        assert not verify_encryption_key(encryption_key, wrong_verifying_key, signature)

    def test_wrong_encryption_key_fails(self) -> None:
        """Signature verified against a different encryption key returns False."""
        signing_key, verifying_key = generate_ed25519_keypair()
        encryption_key = random_encryption_key()
        different_encryption_key = random_encryption_key()

        signature = sign_encryption_key(encryption_key, signing_key)

        assert not verify_encryption_key(
            different_encryption_key, verifying_key, signature
        )

    def test_corrupted_signature_fails(self) -> None:
        """A signature with a flipped byte fails verification."""
        signing_key, verifying_key = generate_ed25519_keypair()
        encryption_key = random_encryption_key()

        signature = sign_encryption_key(encryption_key, signing_key)

        # Flip one byte of the signature
        corrupted = bytearray(signature)
        corrupted[0] ^= 0xFF
        corrupted = bytes(corrupted)

        assert not verify_encryption_key(encryption_key, verifying_key, corrupted)

    def test_all_zeros_signature_fails(self) -> None:
        """An all-zeros signature (valid length) fails verification."""
        _, verifying_key = generate_ed25519_keypair()
        encryption_key = random_encryption_key()

        zero_sig = bytes(SIGNATURE_SIZE)

        assert not verify_encryption_key(encryption_key, verifying_key, zero_sig)


# =============================================================================
# Fingerprint Tests
# =============================================================================


class TestFingerprint:
    """Test fingerprint generation."""

    def test_fingerprint_format(self) -> None:
        """Fingerprint has format 'XXXX XXXX XXXX XXXX'."""
        key = bytes(32)
        fp = fingerprint(key)

        # 4 groups of 4 hex chars separated by spaces = 4*4 + 3 = 19 chars
        assert len(fp) == 19

        import re

        assert re.match(r"^[0-9A-F]{4} [0-9A-F]{4} [0-9A-F]{4} [0-9A-F]{4}$", fp)

    def test_fingerprint_format_with_multiple_keys(self) -> None:
        """Multiple random keys all produce correctly formatted fingerprints."""
        import re

        pattern = re.compile(
            r"^[0-9A-F]{4} [0-9A-F]{4} [0-9A-F]{4} [0-9A-F]{4}$"
        )

        for _ in range(10):
            key = random_encryption_key()
            fp = fingerprint(key)
            assert pattern.match(fp), f"Fingerprint '{fp}' does not match expected format"

    def test_fingerprint_is_deterministic(self) -> None:
        """Same key bytes always produce the same fingerprint."""
        key = bytes([123] * 32)

        fp1 = fingerprint(key)
        fp2 = fingerprint(key)

        assert fp1 == fp2

    def test_fingerprint_same_bytes_different_objects(self) -> None:
        """Two separate byte objects with same content produce the same fingerprint."""
        key1 = bytes(range(32))
        key2 = bytes(range(32))

        assert fingerprint(key1) == fingerprint(key2)

    def test_fingerprint_different_keys_differ(self) -> None:
        """Different keys produce different fingerprints."""
        key1 = bytes([1] * 32)
        key2 = bytes([2] * 32)

        assert fingerprint(key1) != fingerprint(key2)

    def test_fingerprint_empty_input(self) -> None:
        """Fingerprint works on empty bytes (SHA-256 of empty = known value)."""
        import re

        fp = fingerprint(b"")
        pattern = re.compile(
            r"^[0-9A-F]{4} [0-9A-F]{4} [0-9A-F]{4} [0-9A-F]{4}$"
        )
        assert pattern.match(fp), f"Fingerprint of empty input '{fp}' should match format"

    def test_fingerprint_single_byte_input(self) -> None:
        """Fingerprint works on a single byte."""
        import re

        fp = fingerprint(b"\x42")
        pattern = re.compile(
            r"^[0-9A-F]{4} [0-9A-F]{4} [0-9A-F]{4} [0-9A-F]{4}$"
        )
        assert pattern.match(fp), f"Fingerprint of single byte '{fp}' should match format"

    def test_fingerprint_known_value(self) -> None:
        """Fingerprint of all-zero key matches known SHA-256 prefix."""
        import hashlib

        key = bytes(32)
        expected_hash = hashlib.sha256(key).digest()[:8]
        expected_hex = expected_hash.hex().upper()
        expected_fp = " ".join(
            expected_hex[i : i + 4] for i in range(0, len(expected_hex), 4)
        )

        assert fingerprint(key) == expected_fp


# =============================================================================
# Invalid Input Length Tests
# =============================================================================


class TestInvalidInputLengths:
    """Test that invalid input lengths raise ValueError."""

    def test_sign_rejects_short_encryption_key(self) -> None:
        """Signing with a too-short encryption key raises ValueError."""
        signing_key, _ = generate_ed25519_keypair()

        with pytest.raises(ValueError, match="32 bytes"):
            sign_encryption_key(b"too short", signing_key)

    def test_sign_rejects_long_encryption_key(self) -> None:
        """Signing with a too-long encryption key raises ValueError."""
        signing_key, _ = generate_ed25519_keypair()

        with pytest.raises(ValueError, match="32 bytes"):
            sign_encryption_key(bytes(64), signing_key)

    def test_sign_rejects_empty_encryption_key(self) -> None:
        """Signing with an empty encryption key raises ValueError."""
        signing_key, _ = generate_ed25519_keypair()

        with pytest.raises(ValueError, match="32 bytes"):
            sign_encryption_key(b"", signing_key)

    def test_verify_rejects_short_encryption_key(self) -> None:
        """Verifying with a too-short encryption key raises ValueError."""
        _, verifying_key = generate_ed25519_keypair()
        signature = bytes(SIGNATURE_SIZE)

        with pytest.raises(ValueError, match="32 bytes"):
            verify_encryption_key(b"short", verifying_key, signature)

    def test_verify_rejects_long_encryption_key(self) -> None:
        """Verifying with a too-long encryption key raises ValueError."""
        _, verifying_key = generate_ed25519_keypair()
        signature = bytes(SIGNATURE_SIZE)

        with pytest.raises(ValueError, match="32 bytes"):
            verify_encryption_key(bytes(64), verifying_key, signature)

    def test_verify_rejects_short_signature(self) -> None:
        """Verifying with a too-short signature raises ValueError."""
        _, verifying_key = generate_ed25519_keypair()
        encryption_key = random_encryption_key()

        with pytest.raises(ValueError, match=f"{SIGNATURE_SIZE} bytes"):
            verify_encryption_key(encryption_key, verifying_key, bytes(32))

    def test_verify_rejects_empty_signature(self) -> None:
        """Verifying with an empty signature raises ValueError."""
        _, verifying_key = generate_ed25519_keypair()
        encryption_key = random_encryption_key()

        with pytest.raises(ValueError, match=f"{SIGNATURE_SIZE} bytes"):
            verify_encryption_key(encryption_key, verifying_key, b"")

    def test_verify_rejects_long_signature(self) -> None:
        """Verifying with a too-long signature raises ValueError."""
        _, verifying_key = generate_ed25519_keypair()
        encryption_key = random_encryption_key()

        with pytest.raises(ValueError, match=f"{SIGNATURE_SIZE} bytes"):
            verify_encryption_key(encryption_key, verifying_key, bytes(128))


# =============================================================================
# verify_encryption_key_bytes Tests
# =============================================================================


class TestVerifyEncryptionKeyBytes:
    """Test the verify_encryption_key_bytes convenience function."""

    def test_round_trip_succeeds(self) -> None:
        """Sign with key object, verify with raw public key bytes."""
        signing_key, verifying_key = generate_ed25519_keypair()
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        ed25519_public_bytes = verifying_key.public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        encryption_key = random_encryption_key()

        signature = sign_encryption_key(encryption_key, signing_key)

        assert verify_encryption_key_bytes(
            encryption_key, ed25519_public_bytes, signature
        )

    def test_wrong_public_key_bytes_fails(self) -> None:
        """Verification with wrong Ed25519 public key bytes fails."""
        signing_key, _ = generate_ed25519_keypair()
        _, wrong_key = generate_ed25519_keypair()
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        wrong_bytes = wrong_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        encryption_key = random_encryption_key()

        signature = sign_encryption_key(encryption_key, signing_key)

        assert not verify_encryption_key_bytes(
            encryption_key, wrong_bytes, signature
        )

    def test_rejects_wrong_ed25519_key_size(self) -> None:
        """Invalid Ed25519 public key lengths raise ValueError."""
        encryption_key = random_encryption_key()
        signature = bytes(SIGNATURE_SIZE)

        with pytest.raises(ValueError, match="32 bytes"):
            verify_encryption_key_bytes(encryption_key, bytes(16), signature)

        with pytest.raises(ValueError, match="32 bytes"):
            verify_encryption_key_bytes(encryption_key, b"", signature)

        with pytest.raises(ValueError, match="32 bytes"):
            verify_encryption_key_bytes(encryption_key, bytes(64), signature)

    def test_matches_verify_encryption_key(self) -> None:
        """verify_encryption_key_bytes produces same result as verify_encryption_key."""
        signing_key, verifying_key = generate_ed25519_keypair()
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        ed25519_public_bytes = verifying_key.public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        encryption_key = random_encryption_key()
        signature = sign_encryption_key(encryption_key, signing_key)

        result_obj = verify_encryption_key(encryption_key, verifying_key, signature)
        result_bytes = verify_encryption_key_bytes(
            encryption_key, ed25519_public_bytes, signature
        )

        assert result_obj == result_bytes
