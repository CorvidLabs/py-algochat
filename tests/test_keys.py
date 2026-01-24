"""Tests for key derivation."""

import pytest
from algochat.keys import derive_keys_from_seed, public_key_to_bytes
from .test_vectors import (
    ALICE_SEED_HEX,
    BOB_SEED_HEX,
    ALICE_PUBLIC_KEY_HEX,
    BOB_PUBLIC_KEY_HEX,
)


class TestKeyDerivation:
    """Test X25519 key derivation from seeds."""

    def test_derive_alice_keys(self) -> None:
        """Derive Alice's keys and verify public key matches expected."""
        seed = bytes.fromhex(ALICE_SEED_HEX)
        private_key, public_key = derive_keys_from_seed(seed)

        public_bytes = public_key_to_bytes(public_key)
        assert public_bytes.hex() == ALICE_PUBLIC_KEY_HEX

    def test_derive_bob_keys(self) -> None:
        """Derive Bob's keys and verify public key matches expected."""
        seed = bytes.fromhex(BOB_SEED_HEX)
        private_key, public_key = derive_keys_from_seed(seed)

        public_bytes = public_key_to_bytes(public_key)
        assert public_bytes.hex() == BOB_PUBLIC_KEY_HEX

    def test_invalid_seed_length(self) -> None:
        """Reject seeds that are not 32 bytes."""
        with pytest.raises(ValueError, match="32 bytes"):
            derive_keys_from_seed(b"too short")

        with pytest.raises(ValueError, match="32 bytes"):
            derive_keys_from_seed(b"x" * 64)

    def test_deterministic_derivation(self) -> None:
        """Same seed always produces same keys."""
        seed = bytes.fromhex(ALICE_SEED_HEX)

        private1, public1 = derive_keys_from_seed(seed)
        private2, public2 = derive_keys_from_seed(seed)

        assert public_key_to_bytes(public1) == public_key_to_bytes(public2)
