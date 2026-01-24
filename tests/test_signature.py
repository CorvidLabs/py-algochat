"""Tests for signature module."""

import os
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from algochat.signature import (
    sign_encryption_key,
    sign_encryption_key_bytes,
    verify_encryption_key,
    verify_encryption_key_bytes,
    get_public_key,
    fingerprint,
    SignatureError,
    ED25519_SIGNATURE_SIZE,
)


class TestSignAndVerify:
    """Tests for sign and verify roundtrip."""

    def test_sign_and_verify_roundtrip(self):
        """Test that signed keys can be verified."""
        signing_key = Ed25519PrivateKey.generate()
        verifying_key = signing_key.public_key()

        # Fake X25519 public key (32 bytes)
        encryption_key = bytes([42] * 32)

        signature = sign_encryption_key(encryption_key, signing_key)
        assert len(signature) == ED25519_SIGNATURE_SIZE

        valid = verify_encryption_key(encryption_key, verifying_key, signature)
        assert valid is True

    def test_sign_and_verify_bytes(self):
        """Test sign and verify using raw byte APIs."""
        signing_key_bytes = os.urandom(32)
        signing_key = Ed25519PrivateKey.from_private_bytes(signing_key_bytes)
        verifying_key_bytes = signing_key.public_key().public_bytes_raw()

        encryption_key = bytes([42] * 32)

        signature = sign_encryption_key_bytes(encryption_key, signing_key_bytes)
        assert len(signature) == ED25519_SIGNATURE_SIZE

        valid = verify_encryption_key_bytes(encryption_key, verifying_key_bytes, signature)
        assert valid is True

    def test_verify_wrong_key_fails(self):
        """Test that verification fails with wrong key."""
        signing_key = Ed25519PrivateKey.generate()
        wrong_key = Ed25519PrivateKey.generate().public_key()

        encryption_key = bytes([42] * 32)
        signature = sign_encryption_key(encryption_key, signing_key)

        valid = verify_encryption_key(encryption_key, wrong_key, signature)
        assert valid is False

    def test_verify_wrong_message_fails(self):
        """Test that verification fails with wrong message."""
        signing_key = Ed25519PrivateKey.generate()
        verifying_key = signing_key.public_key()

        encryption_key = bytes([42] * 32)
        wrong_key = bytes([99] * 32)

        signature = sign_encryption_key(encryption_key, signing_key)

        valid = verify_encryption_key(wrong_key, verifying_key, signature)
        assert valid is False


class TestFingerprint:
    """Tests for fingerprint generation."""

    def test_fingerprint_format(self):
        """Test fingerprint has correct format."""
        key = bytes(32)
        fp = fingerprint(key)

        # Should be 4 groups of 4 hex chars separated by spaces
        assert len(fp) == 19  # "XXXX XXXX XXXX XXXX"
        parts = fp.split(" ")
        assert len(parts) == 4
        for part in parts:
            assert len(part) == 4
            assert all(c in "0123456789ABCDEF" for c in part)

    def test_fingerprint_deterministic(self):
        """Test fingerprint is deterministic."""
        key = bytes([123] * 32)
        fp1 = fingerprint(key)
        fp2 = fingerprint(key)

        assert fp1 == fp2

    def test_different_keys_different_fingerprints(self):
        """Test different keys produce different fingerprints."""
        key1 = bytes([1] * 32)
        key2 = bytes([2] * 32)

        assert fingerprint(key1) != fingerprint(key2)


class TestGetPublicKey:
    """Tests for get_public_key function."""

    def test_get_public_key_from_object(self):
        """Test getting public key from Ed25519PrivateKey object."""
        private_key = Ed25519PrivateKey.generate()
        expected = private_key.public_key().public_bytes_raw()

        result = get_public_key(private_key)
        assert result == expected

    def test_get_public_key_from_bytes(self):
        """Test getting public key from raw bytes."""
        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes_raw()
        expected = private_key.public_key().public_bytes_raw()

        result = get_public_key(private_bytes)
        assert result == expected


class TestErrorHandling:
    """Tests for error handling."""

    def test_invalid_encryption_key_length(self):
        """Test error on invalid encryption key length."""
        signing_key = Ed25519PrivateKey.generate()

        with pytest.raises(SignatureError):
            sign_encryption_key(bytes(16), signing_key)

    def test_invalid_signing_key_bytes_length(self):
        """Test error on invalid signing key bytes length."""
        with pytest.raises(SignatureError):
            sign_encryption_key_bytes(bytes(32), bytes(16))

    def test_invalid_signature_length(self):
        """Test error on invalid signature length."""
        verifying_key = Ed25519PrivateKey.generate().public_key()

        with pytest.raises(SignatureError):
            verify_encryption_key(bytes(32), verifying_key, bytes(32))

    def test_invalid_verifying_key_bytes_length(self):
        """Test error on invalid verifying key bytes length."""
        with pytest.raises(SignatureError):
            verify_encryption_key_bytes(bytes(32), bytes(16), bytes(64))
