"""Tests for PSK (Pre-Shared Key) v1.1 protocol."""

import pytest
from algochat.keys import derive_keys_from_seed, public_key_to_bytes
from algochat.psk_types import (
    PSK_VERSION,
    PSK_PROTOCOL_ID,
    PSK_HEADER_SIZE,
    PSKEnvelope,
)
from algochat.psk_ratchet import (
    derive_session_psk,
    derive_position_psk,
    derive_psk_at_counter,
)
from algochat.psk_envelope import (
    encode_psk_envelope,
    decode_psk_envelope,
    is_psk_message,
    PSKEnvelopeError,
)
from algochat.psk_crypto import (
    encrypt_psk_message,
    decrypt_psk_message,
)
from algochat.psk_state import (
    PSKState,
    validate_counter,
    record_receive,
    advance_send_counter,
)
from algochat.psk_exchange import (
    create_psk_exchange_uri,
    parse_psk_exchange_uri,
)
from .test_vectors import ALICE_SEED_HEX, BOB_SEED_HEX


# Test PSK: 0xAA repeated 32 times
TEST_PSK = bytes([0xAA] * 32)


class TestPSKRatchetVectors:
    """Verify PSK ratchet derivation against known test vectors."""

    def test_session_0(self) -> None:
        """Session PSK at index 0 matches expected."""
        result = derive_session_psk(TEST_PSK, 0)
        assert result.hex() == "a031707ea9e9e50bd8ea4eb9a2bd368465ea1aff14caab293d38954b4717e888"

    def test_session_1(self) -> None:
        """Session PSK at index 1 matches expected."""
        result = derive_session_psk(TEST_PSK, 1)
        assert result.hex() == "994cffbb4f84fa5410d44574bb9fa7408a8c2f1ed2b3a00f5168fc74c71f7cea"

    def test_counter_0(self) -> None:
        """PSK at counter 0 matches expected."""
        result = derive_psk_at_counter(TEST_PSK, 0)
        assert result.hex() == "2918fd486b9bd024d712f6234b813c0f4167237d60c2c1fca37326b20497c165"

    def test_counter_99(self) -> None:
        """PSK at counter 99 matches expected."""
        result = derive_psk_at_counter(TEST_PSK, 99)
        assert result.hex() == "5b48a50a25261f6b63fe9c867b46be46de4d747c3477db6290045ba519a4d38b"

    def test_counter_100(self) -> None:
        """PSK at counter 100 (session boundary) matches expected."""
        result = derive_psk_at_counter(TEST_PSK, 100)
        assert result.hex() == "7a15d3add6a28858e6a1f1ea0d22bdb29b7e129a1330c4908d9b46a460992694"

    def test_counter_100_is_session_1_position_0(self) -> None:
        """Counter 100 should equal session 1, position 0."""
        from_counter = derive_psk_at_counter(TEST_PSK, 100)

        session1 = derive_session_psk(TEST_PSK, 1)
        from_components = derive_position_psk(session1, 0)

        assert from_counter == from_components


class TestPSKEnvelopeEncodeDecode:
    """Test PSK envelope encode/decode round trip."""

    def test_encode_decode_round_trip(self) -> None:
        """Encoded envelope decodes back to original values."""
        original = PSKEnvelope(
            ratchet_counter=42,
            sender_public_key=bytes(range(32)),
            ephemeral_public_key=bytes(range(32, 64)),
            nonce=bytes(range(12)),
            encrypted_sender_key=bytes(range(48)),
            ciphertext=b"hello encrypted",
        )

        encoded = encode_psk_envelope(original)
        decoded = decode_psk_envelope(encoded)

        assert decoded.ratchet_counter == original.ratchet_counter
        assert decoded.sender_public_key == original.sender_public_key
        assert decoded.ephemeral_public_key == original.ephemeral_public_key
        assert decoded.nonce == original.nonce
        assert decoded.encrypted_sender_key == original.encrypted_sender_key
        assert decoded.ciphertext == original.ciphertext

    def test_header_format(self) -> None:
        """Encoded envelope has correct header format."""
        envelope = PSKEnvelope(
            ratchet_counter=256,
            sender_public_key=bytes(32),
            ephemeral_public_key=bytes(32),
            nonce=bytes(12),
            encrypted_sender_key=bytes(48),
            ciphertext=b"test",
        )

        encoded = encode_psk_envelope(envelope)

        assert encoded[0] == PSK_VERSION
        assert encoded[1] == PSK_PROTOCOL_ID
        assert len(encoded) == PSK_HEADER_SIZE + len(b"test")

        # Verify ratchet counter encoding (256 = 0x00000100)
        counter_bytes = encoded[2:6]
        assert int.from_bytes(counter_bytes, byteorder="big") == 256

    def test_is_psk_message(self) -> None:
        """is_psk_message correctly identifies PSK envelopes."""
        envelope = PSKEnvelope(
            ratchet_counter=0,
            sender_public_key=bytes(32),
            ephemeral_public_key=bytes(32),
            nonce=bytes(12),
            encrypted_sender_key=bytes(48),
            ciphertext=b"test",
        )
        encoded = encode_psk_envelope(envelope)

        assert is_psk_message(encoded)
        assert not is_psk_message(b"too short")
        assert not is_psk_message(bytes(200))  # all zeros

    def test_decode_too_short(self) -> None:
        """Decoding too-short data raises error."""
        with pytest.raises(PSKEnvelopeError, match="too short"):
            decode_psk_envelope(b"short")

    def test_decode_wrong_version(self) -> None:
        """Decoding wrong version raises error."""
        data = bytes([0x99, PSK_PROTOCOL_ID]) + bytes(128)
        with pytest.raises(PSKEnvelopeError, match="version"):
            decode_psk_envelope(data)

    def test_decode_wrong_protocol(self) -> None:
        """Decoding wrong protocol ID raises error."""
        data = bytes([PSK_VERSION, 0x99]) + bytes(128)
        with pytest.raises(PSKEnvelopeError, match="protocol"):
            decode_psk_envelope(data)


class TestPSKEncryptDecrypt:
    """Test PSK encrypt/decrypt round trip."""

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

    def test_encrypt_decrypt_as_recipient(self, alice_keys, bob_keys) -> None:
        """Bob can decrypt a PSK message from Alice."""
        alice_private, alice_public = alice_keys
        bob_private, bob_public = bob_keys
        psk = derive_psk_at_counter(TEST_PSK, 0)

        envelope = encrypt_psk_message(
            "Hello PSK!",
            alice_private,
            alice_public,
            bob_public,
            psk,
            0,
        )

        result = decrypt_psk_message(envelope, bob_private, bob_public, psk)
        assert result == "Hello PSK!"

    def test_encrypt_decrypt_as_sender(self, alice_keys, bob_keys) -> None:
        """Alice can decrypt her own PSK message (bidirectional)."""
        alice_private, alice_public = alice_keys
        _, bob_public = bob_keys
        psk = derive_psk_at_counter(TEST_PSK, 5)

        envelope = encrypt_psk_message(
            "Self-decrypt test",
            alice_private,
            alice_public,
            bob_public,
            psk,
            5,
        )

        result = decrypt_psk_message(envelope, alice_private, alice_public, psk)
        assert result == "Self-decrypt test"

    def test_full_round_trip_with_encoding(self, alice_keys, bob_keys) -> None:
        """Full round trip: encrypt -> encode -> decode -> decrypt."""
        alice_private, alice_public = alice_keys
        bob_private, bob_public = bob_keys
        psk = derive_psk_at_counter(TEST_PSK, 42)

        envelope = encrypt_psk_message(
            "Round trip PSK",
            alice_private,
            alice_public,
            bob_public,
            psk,
            42,
        )

        encoded = encode_psk_envelope(envelope)
        assert is_psk_message(encoded)

        decoded = decode_psk_envelope(encoded)
        result = decrypt_psk_message(decoded, bob_private, bob_public, psk)
        assert result == "Round trip PSK"

    def test_different_counters_different_keys(self, alice_keys, bob_keys) -> None:
        """Messages at different counters use different derived keys."""
        alice_private, alice_public = alice_keys
        bob_private, bob_public = bob_keys

        psk0 = derive_psk_at_counter(TEST_PSK, 0)
        psk1 = derive_psk_at_counter(TEST_PSK, 1)

        envelope = encrypt_psk_message(
            "Counter 0 message",
            alice_private,
            alice_public,
            bob_public,
            psk0,
            0,
        )

        # Should succeed with correct PSK
        result = decrypt_psk_message(envelope, bob_private, bob_public, psk0)
        assert result == "Counter 0 message"

        # Should fail with wrong PSK
        with pytest.raises(Exception):
            decrypt_psk_message(envelope, bob_private, bob_public, psk1)

    def test_unicode_message(self, alice_keys, bob_keys) -> None:
        """PSK encryption handles unicode messages."""
        alice_private, alice_public = alice_keys
        bob_private, bob_public = bob_keys
        psk = derive_psk_at_counter(TEST_PSK, 0)

        message = "Hello 👋 World 🌍"
        envelope = encrypt_psk_message(
            message,
            alice_private,
            alice_public,
            bob_public,
            psk,
            0,
        )

        result = decrypt_psk_message(envelope, bob_private, bob_public, psk)
        assert result == message

    def test_empty_message(self, alice_keys, bob_keys) -> None:
        """PSK encryption handles empty messages."""
        alice_private, alice_public = alice_keys
        bob_private, bob_public = bob_keys
        psk = derive_psk_at_counter(TEST_PSK, 0)

        envelope = encrypt_psk_message(
            "",
            alice_private,
            alice_public,
            bob_public,
            psk,
            0,
        )

        result = decrypt_psk_message(envelope, bob_private, bob_public, psk)
        assert result == ""


class TestPSKState:
    """Test PSK counter state management."""

    def test_initial_state(self) -> None:
        """Initial state has zero counters."""
        state = PSKState()
        assert state.send_counter == 0
        assert state.peer_last_counter == -1
        assert len(state.seen_counters) == 0

    def test_advance_send_counter(self) -> None:
        """Send counter advances correctly."""
        state = PSKState()

        counter, state = advance_send_counter(state)
        assert counter == 0
        assert state.send_counter == 1

        counter, state = advance_send_counter(state)
        assert counter == 1
        assert state.send_counter == 2

    def test_validate_counter_fresh(self) -> None:
        """Fresh counters are valid."""
        state = PSKState()
        assert validate_counter(state, 0)
        assert validate_counter(state, 1)
        assert validate_counter(state, 100)

    def test_validate_counter_negative(self) -> None:
        """Negative counters are rejected."""
        state = PSKState()
        assert not validate_counter(state, -1)
        assert not validate_counter(state, -100)

    def test_validate_counter_replay(self) -> None:
        """Already-seen counters are rejected (replay protection)."""
        state = PSKState()
        state = record_receive(state, 5)
        assert not validate_counter(state, 5)

    def test_validate_counter_window(self) -> None:
        """Counters outside the window are rejected."""
        state = PSKState()
        state = record_receive(state, 300)

        # Within window (300 - 200 = 100)
        assert validate_counter(state, 100)
        assert validate_counter(state, 200)
        assert validate_counter(state, 299)

        # Outside window
        assert not validate_counter(state, 99)
        assert not validate_counter(state, 0)

    def test_record_receive(self) -> None:
        """Recording a receive updates state correctly."""
        state = PSKState()

        state = record_receive(state, 5)
        assert state.peer_last_counter == 5
        assert 5 in state.seen_counters

        state = record_receive(state, 3)
        assert state.peer_last_counter == 5  # Still 5 (higher)
        assert 3 in state.seen_counters
        assert 5 in state.seen_counters

        state = record_receive(state, 10)
        assert state.peer_last_counter == 10
        assert 10 in state.seen_counters

    def test_record_receive_prunes_old(self) -> None:
        """Recording a high counter prunes old seen counters."""
        state = PSKState()

        # Record some early counters
        state = record_receive(state, 0)
        state = record_receive(state, 1)
        state = record_receive(state, 2)

        # Jump far ahead
        state = record_receive(state, 500)

        # Old counters should be pruned (500 - 200 = 300 lower bound)
        assert 0 not in state.seen_counters
        assert 1 not in state.seen_counters
        assert 2 not in state.seen_counters
        assert 500 in state.seen_counters


class TestPSKExchangeURI:
    """Test PSK exchange URI encode/parse."""

    def test_create_uri_without_label(self) -> None:
        """Create URI without label."""
        address = "TESTADDR123"
        psk = bytes(32)

        uri = create_psk_exchange_uri(address, psk)

        assert uri.startswith("algochat-psk://v1?")
        assert "addr=TESTADDR123" in uri
        assert "psk=" in uri
        assert "label=" not in uri

    def test_create_uri_with_label(self) -> None:
        """Create URI with label."""
        address = "TESTADDR123"
        psk = bytes(32)

        uri = create_psk_exchange_uri(address, psk, label="My Chat")

        assert "label=My" in uri or "label=My+Chat" in uri or "label=My%20Chat" in uri

    def test_parse_uri(self) -> None:
        """Parse a valid PSK exchange URI."""
        psk = bytes([0xBB] * 32)
        address = "TESTADDR456"

        uri = create_psk_exchange_uri(address, psk, label="Test")
        parsed = parse_psk_exchange_uri(uri)

        assert parsed["address"] == address
        assert parsed["psk"] == psk
        assert parsed["label"] == "Test"

    def test_round_trip(self) -> None:
        """URI round-trips correctly."""
        psk = bytes(range(32))
        address = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

        uri = create_psk_exchange_uri(address, psk)
        parsed = parse_psk_exchange_uri(uri)

        assert parsed["address"] == address
        assert parsed["psk"] == psk
        assert "label" not in parsed

    def test_parse_invalid_scheme(self) -> None:
        """Parsing invalid scheme raises ValueError."""
        with pytest.raises(ValueError, match="scheme"):
            parse_psk_exchange_uri("https://v1?addr=X&psk=Y")

    def test_parse_missing_addr(self) -> None:
        """Parsing URI without addr raises ValueError."""
        with pytest.raises(ValueError, match="addr"):
            parse_psk_exchange_uri("algochat-psk://v1?psk=AAAA")

    def test_parse_missing_psk(self) -> None:
        """Parsing URI without psk raises ValueError."""
        with pytest.raises(ValueError, match="psk"):
            parse_psk_exchange_uri("algochat-psk://v1?addr=X")
