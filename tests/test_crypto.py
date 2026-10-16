"""Tests for encryption and decryption."""

import pytest
from algochat.keys import derive_keys_from_seed, public_key_to_bytes
from algochat.crypto import encrypt_message, decrypt_message
from algochat.envelope import encode_envelope, decode_envelope, is_chat_message
from algochat.types import (
    HEADER_SIZE,
    TAG_SIZE,
    MAX_NOTE_SIZE,
    MAX_PAYLOAD_SIZE,
    EncryptionError,
    payment_fee,
)
from .test_vectors import (
    ALICE_SEED_HEX,
    BOB_SEED_HEX,
    TEST_MESSAGES,
)


class TestEncryption:
    """Test message encryption."""

    @pytest.fixture
    def alice_keys(self):
        """Alice's key pair."""
        seed = bytes.fromhex(ALICE_SEED_HEX)
        return derive_keys_from_seed(seed)

    @pytest.fixture
    def bob_keys(self):
        """Bob's key pair."""
        seed = bytes.fromhex(BOB_SEED_HEX)
        return derive_keys_from_seed(seed)

    def test_encrypt_simple_message(self, alice_keys, bob_keys) -> None:
        """Encrypt a simple message from Alice to Bob."""
        alice_private, alice_public = alice_keys
        bob_private, bob_public = bob_keys

        envelope = encrypt_message(
            "Hello, Bob!",
            alice_private,
            alice_public,
            bob_public,
        )

        assert envelope.version == 0x01
        assert envelope.protocol_id == 0x01
        assert envelope.sender_public_key == public_key_to_bytes(alice_public)
        assert len(envelope.ephemeral_public_key) == 32
        assert len(envelope.nonce) == 12
        assert len(envelope.encrypted_sender_key) == 48
        assert len(envelope.ciphertext) > 0

    def test_envelope_encoding(self, alice_keys, bob_keys) -> None:
        """Encoded envelope has correct format."""
        alice_private, alice_public = alice_keys
        _, bob_public = bob_keys

        envelope = encrypt_message(
            "Test message",
            alice_private,
            alice_public,
            bob_public,
        )

        encoded = encode_envelope(envelope)
        assert len(encoded) >= HEADER_SIZE
        assert encoded[0] == 0x01  # version
        assert encoded[1] == 0x01  # protocol ID

        # Verify is_chat_message works
        assert is_chat_message(encoded)
        assert not is_chat_message(b"invalid")
        assert not is_chat_message(bytes(100))  # zeros


class TestDecryption:
    """Test message decryption."""

    @pytest.fixture
    def alice_keys(self):
        """Alice's key pair."""
        seed = bytes.fromhex(ALICE_SEED_HEX)
        return derive_keys_from_seed(seed)

    @pytest.fixture
    def bob_keys(self):
        """Bob's key pair."""
        seed = bytes.fromhex(BOB_SEED_HEX)
        return derive_keys_from_seed(seed)

    def test_decrypt_as_recipient(self, alice_keys, bob_keys) -> None:
        """Bob can decrypt message from Alice."""
        alice_private, alice_public = alice_keys
        bob_private, bob_public = bob_keys

        original_message = "Hello from Alice!"

        envelope = encrypt_message(
            original_message,
            alice_private,
            alice_public,
            bob_public,
        )

        result = decrypt_message(envelope, bob_private, bob_public)

        assert result is not None
        assert result.text == original_message

    def test_decrypt_as_sender(self, alice_keys, bob_keys) -> None:
        """Alice can decrypt her own message (bidirectional)."""
        alice_private, alice_public = alice_keys
        _, bob_public = bob_keys

        original_message = "I sent this!"

        envelope = encrypt_message(
            original_message,
            alice_private,
            alice_public,
            bob_public,
        )

        result = decrypt_message(envelope, alice_private, alice_public)

        assert result is not None
        assert result.text == original_message

    def test_round_trip_encode_decode(self, alice_keys, bob_keys) -> None:
        """Full round trip: encrypt -> encode -> decode -> decrypt."""
        alice_private, alice_public = alice_keys
        bob_private, bob_public = bob_keys

        original_message = "Round trip test!"

        envelope = encrypt_message(
            original_message,
            alice_private,
            alice_public,
            bob_public,
        )

        encoded = encode_envelope(envelope)
        decoded = decode_envelope(encoded)

        result = decrypt_message(decoded, bob_private, bob_public)

        assert result is not None
        assert result.text == original_message


class TestMultiMessageEncryption:
    """Test all message types encrypt/decrypt correctly."""

    @pytest.fixture
    def alice_keys(self):
        """Alice's key pair."""
        seed = bytes.fromhex(ALICE_SEED_HEX)
        return derive_keys_from_seed(seed)

    @pytest.fixture
    def bob_keys(self):
        """Bob's key pair."""
        seed = bytes.fromhex(BOB_SEED_HEX)
        return derive_keys_from_seed(seed)

    @pytest.mark.parametrize("message_key,message", TEST_MESSAGES.items())
    def test_message_round_trip(
        self, alice_keys, bob_keys, message_key: str, message: str
    ) -> None:
        """Each test message encrypts and decrypts correctly."""
        alice_private, alice_public = alice_keys
        bob_private, bob_public = bob_keys

        envelope = encrypt_message(
            message,
            alice_private,
            alice_public,
            bob_public,
        )

        # Verify as recipient
        result_bob = decrypt_message(envelope, bob_private, bob_public)
        assert result_bob is not None, f"Failed to decrypt {message_key} as recipient"
        assert result_bob.text == message, f"Message mismatch for {message_key}"

        # Verify as sender (bidirectional)
        result_alice = decrypt_message(envelope, alice_private, alice_public)
        assert result_alice is not None, f"Failed to decrypt {message_key} as sender"
        assert result_alice.text == message, f"Bidirectional mismatch for {message_key}"

    @pytest.mark.parametrize("message_key,message", TEST_MESSAGES.items())
    def test_message_full_round_trip(
        self, alice_keys, bob_keys, message_key: str, message: str
    ) -> None:
        """Each test message survives full encode/decode cycle."""
        alice_private, alice_public = alice_keys
        bob_private, bob_public = bob_keys

        envelope = encrypt_message(
            message,
            alice_private,
            alice_public,
            bob_public,
        )

        encoded = encode_envelope(envelope)
        assert is_chat_message(encoded)
        assert len(encoded) >= HEADER_SIZE

        decoded = decode_envelope(encoded)
        result = decrypt_message(decoded, bob_private, bob_public)

        assert result is not None, f"Failed to decrypt encoded {message_key}"
        assert result.text == message, f"Encoded message mismatch for {message_key}"


class TestNoteCapacity:
    """Note ceiling is 4096 bytes. Headers and the tag are unchanged."""

    @pytest.fixture
    def alice_keys(self):
        """Alice's key pair."""
        seed = bytes.fromhex(ALICE_SEED_HEX)
        return derive_keys_from_seed(seed)

    @pytest.fixture
    def bob_keys(self):
        """Bob's key pair."""
        seed = bytes.fromhex(BOB_SEED_HEX)
        return derive_keys_from_seed(seed)

    def test_layout_constants(self) -> None:
        """Standard header stays 126 and the tag stays 16."""
        assert HEADER_SIZE == 126
        assert TAG_SIZE == 16
        assert MAX_NOTE_SIZE == 4096
        assert MAX_PAYLOAD_SIZE == 3954
        assert MAX_PAYLOAD_SIZE == MAX_NOTE_SIZE - HEADER_SIZE - TAG_SIZE

    def test_legacy_882_byte_plaintext_succeeds(self, alice_keys, bob_keys) -> None:
        """An 882-byte plaintext still encrypts, and the note is at most 1024 bytes."""
        alice_private, alice_public = alice_keys
        bob_private, bob_public = bob_keys
        message = "A" * 882

        envelope = encrypt_message(message, alice_private, alice_public, bob_public)
        encoded = encode_envelope(envelope)

        assert len(encoded) == HEADER_SIZE + 882 + TAG_SIZE
        assert len(encoded) <= 1024
        decoded = decode_envelope(encoded)
        result = decrypt_message(decoded, bob_private, bob_public)
        assert result is not None
        assert result.text == message

    def test_max_plaintext_encodes_to_4096(self, alice_keys, bob_keys) -> None:
        """3954 bytes of plaintext encode to a note of exactly 4096 bytes."""
        alice_private, alice_public = alice_keys
        bob_private, bob_public = bob_keys
        message = "A" * MAX_PAYLOAD_SIZE

        envelope = encrypt_message(message, alice_private, alice_public, bob_public)
        encoded = encode_envelope(envelope)

        assert len(encoded) == 4096
        assert len(encoded) == MAX_NOTE_SIZE
        decoded = decode_envelope(encoded)
        result = decrypt_message(decoded, bob_private, bob_public)
        assert result is not None
        assert result.text == message

    def test_one_extra_byte_fails_before_encoding(self, alice_keys, bob_keys) -> None:
        """One byte past 3954 is rejected before a transaction can be built."""
        alice_private, alice_public = alice_keys
        _, bob_public = bob_keys

        with pytest.raises(EncryptionError, match="too large"):
            encrypt_message("A" * (MAX_PAYLOAD_SIZE + 1), alice_private, alice_public, bob_public)

    def test_payment_fees_at_min_fee_1000(self) -> None:
        """Note surcharge at minFee 1000 for 1024, 2000, and 4096 byte notes."""
        assert payment_fee(1024, 1000) == 1000
        assert payment_fee(2000, 1000) == 1098
        assert payment_fee(4096, 1000) == 1308
