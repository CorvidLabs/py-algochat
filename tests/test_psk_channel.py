"""Tests for PSKChannel — high-level PSK conversation manager."""

import os

import pytest

from algochat.keys import derive_keys_from_seed, public_key_to_bytes
from algochat.psk_channel import PSKChannel
from algochat.psk_state import PSKState
from algochat.psk_exchange import parse_psk_exchange_uri
from .test_vectors import ALICE_SEED_HEX, BOB_SEED_HEX


TEST_PSK = bytes([0xAA] * 32)


@pytest.fixture
def alice_keys():
    seed = bytes.fromhex(ALICE_SEED_HEX)
    return derive_keys_from_seed(seed)


@pytest.fixture
def bob_keys():
    seed = bytes.fromhex(BOB_SEED_HEX)
    return derive_keys_from_seed(seed)


@pytest.fixture
def alice_channel(alice_keys, bob_keys):
    """Alice's PSK channel configured to talk to Bob."""
    alice_priv, alice_pub = alice_keys
    _, bob_pub = bob_keys
    ch = PSKChannel(
        initial_psk=TEST_PSK,
        our_private_key=alice_priv,
        our_public_key=alice_pub,
        peer_public_key=bob_pub,
    )
    return ch


@pytest.fixture
def bob_channel(bob_keys, alice_keys):
    """Bob's PSK channel configured to talk to Alice."""
    bob_priv, bob_pub = bob_keys
    _, alice_pub = alice_keys
    ch = PSKChannel(
        initial_psk=TEST_PSK,
        our_private_key=bob_priv,
        our_public_key=bob_pub,
        peer_public_key=alice_pub,
    )
    return ch


class TestPSKChannelBasic:
    """Basic PSKChannel operations."""

    def test_generate_psk(self):
        """generate_psk returns 32 random bytes."""
        psk = PSKChannel.generate_psk()
        assert len(psk) == 32
        # Two calls should produce different keys
        assert psk != PSKChannel.generate_psk()

    def test_invalid_psk_length(self, alice_keys):
        """Constructor rejects wrong-length PSK."""
        priv, pub = alice_keys
        with pytest.raises(ValueError, match="32 bytes"):
            PSKChannel(initial_psk=b"short", our_private_key=priv, our_public_key=pub)

    def test_initial_state(self, alice_channel):
        """New channel starts with zero counters."""
        assert alice_channel.send_counter == 0
        assert alice_channel.peer_last_counter == -1
        assert not alice_channel.is_in_grace_period

    def test_is_psk_data(self, alice_channel):
        """is_psk_data detects PSK envelopes."""
        data = alice_channel.encrypt("test")
        assert PSKChannel.is_psk_data(data)
        assert not PSKChannel.is_psk_data(b"not a psk message")


class TestPSKChannelEncryptDecrypt:
    """Encrypt/decrypt round trips through PSKChannel."""

    def test_basic_round_trip(self, alice_channel, bob_channel):
        """Alice encrypts, Bob decrypts."""
        data = alice_channel.encrypt("Hello Bob!")
        msg = bob_channel.decrypt(data)
        assert msg.text == "Hello Bob!"
        assert msg.counter == 0

    def test_bidirectional(self, alice_channel, bob_channel):
        """Both directions work."""
        # Alice -> Bob
        data1 = alice_channel.encrypt("Hi Bob")
        msg1 = bob_channel.decrypt(data1)
        assert msg1.text == "Hi Bob"

        # Bob -> Alice
        data2 = bob_channel.encrypt("Hi Alice")
        msg2 = alice_channel.decrypt(data2)
        assert msg2.text == "Hi Alice"

    def test_counter_advances(self, alice_channel, bob_channel):
        """Send counter advances with each message."""
        assert alice_channel.send_counter == 0

        alice_channel.encrypt("msg 1")
        assert alice_channel.send_counter == 1

        alice_channel.encrypt("msg 2")
        assert alice_channel.send_counter == 2

    def test_multiple_messages(self, alice_channel, bob_channel):
        """Multiple messages decrypt correctly in order."""
        messages = ["First", "Second", "Third"]
        encrypted = [alice_channel.encrypt(m) for m in messages]

        for i, data in enumerate(encrypted):
            msg = bob_channel.decrypt(data)
            assert msg.text == messages[i]
            assert msg.counter == i

    def test_out_of_order_delivery(self, alice_channel, bob_channel):
        """Out-of-order messages decrypt correctly."""
        data0 = alice_channel.encrypt("msg 0")
        data1 = alice_channel.encrypt("msg 1")
        data2 = alice_channel.encrypt("msg 2")

        # Deliver out of order
        msg2 = bob_channel.decrypt(data2)
        assert msg2.text == "msg 2"

        msg0 = bob_channel.decrypt(data0)
        assert msg0.text == "msg 0"

        msg1 = bob_channel.decrypt(data1)
        assert msg1.text == "msg 1"

    def test_sender_self_decrypt(self, alice_channel):
        """Sender can decrypt their own messages (bidirectional)."""
        data = alice_channel.encrypt("Self-read")

        # Create a separate channel for Alice to act as "receiver of own message"
        # Using the same keys but as recipient
        msg = alice_channel.decrypt(data)
        assert msg.text == "Self-read"

    def test_encrypt_without_peer_key(self, alice_keys):
        """Encrypting without peer key raises ValueError."""
        priv, pub = alice_keys
        ch = PSKChannel(initial_psk=TEST_PSK, our_private_key=priv, our_public_key=pub)

        with pytest.raises(ValueError, match="Peer public key"):
            ch.encrypt("should fail")

    def test_unicode_and_emoji(self, alice_channel, bob_channel):
        """Unicode messages round-trip correctly."""
        msg_text = "Hello 👋 World 🌍 Привет"
        data = alice_channel.encrypt(msg_text)
        msg = bob_channel.decrypt(data)
        assert msg.text == msg_text

    def test_empty_message(self, alice_channel, bob_channel):
        """Empty messages round-trip correctly."""
        data = alice_channel.encrypt("")
        msg = bob_channel.decrypt(data)
        assert msg.text == ""

    def test_session_boundary_crossing(self, alice_channel, bob_channel):
        """Messages across session boundaries (counter 99->100) work."""
        # Set state to just before session boundary
        alice_channel._state = PSKState(send_counter=99)

        data99 = alice_channel.encrypt("Last in session 0")
        data100 = alice_channel.encrypt("First in session 1")

        msg99 = bob_channel.decrypt(data99)
        assert msg99.text == "Last in session 0"
        assert msg99.counter == 99

        msg100 = bob_channel.decrypt(data100)
        assert msg100.text == "First in session 1"
        assert msg100.counter == 100


class TestPSKChannelReplayProtection:
    """Counter validation and replay protection."""

    def test_replay_rejected(self, alice_channel, bob_channel):
        """Same message can't be decrypted twice."""
        data = alice_channel.encrypt("no replay")
        bob_channel.decrypt(data)

        with pytest.raises(ValueError, match="Invalid counter"):
            bob_channel.decrypt(data)

    def test_txid_dedup(self, alice_channel, bob_channel):
        """Duplicate txid is rejected."""
        data = alice_channel.encrypt("dedup test")
        bob_channel.decrypt(data, txid="tx-001")

        data2 = alice_channel.encrypt("different msg")
        with pytest.raises(ValueError, match="Duplicate transaction"):
            bob_channel.decrypt(data2, txid="tx-001")


class TestPSKChannelKeyRotation:
    """PSK key rotation with grace period."""

    def test_rotate_psk(self, alice_channel, bob_channel):
        """After rotation, new messages use new PSK."""
        new_psk = os.urandom(32)

        # Both rotate to same new PSK
        alice_channel.rotate_psk(new_psk)
        bob_channel.rotate_psk(new_psk)

        data = alice_channel.encrypt("After rotation")
        msg = bob_channel.decrypt(data)
        assert msg.text == "After rotation"

    def test_grace_period_active(self, alice_channel):
        """Grace period is active after rotation."""
        assert not alice_channel.is_in_grace_period

        alice_channel.rotate_psk(os.urandom(32), grace_period=60.0)
        assert alice_channel.is_in_grace_period

    def test_grace_period_fallback(self, alice_channel, bob_channel):
        """During grace period, old PSK still works for decryption."""
        # Alice sends with old PSK
        data_old = alice_channel.encrypt("Before rotation")

        # Bob rotates to new PSK with grace period
        new_psk = os.urandom(32)
        bob_channel.rotate_psk(new_psk, grace_period=60.0)

        # Bob can still decrypt Alice's old-PSK message
        msg = bob_channel.decrypt(data_old)
        assert msg.text == "Before rotation"

    def test_invalid_rotation_psk_length(self, alice_channel):
        """Rotation rejects wrong-length PSK."""
        with pytest.raises(ValueError, match="32 bytes"):
            alice_channel.rotate_psk(b"too short")


class TestPSKChannelReset:
    """Channel reset behavior."""

    def test_reset_clears_state(self, alice_channel):
        """Reset clears all counters."""
        alice_channel.encrypt("advance counter")
        assert alice_channel.send_counter == 1

        alice_channel.reset()
        assert alice_channel.send_counter == 0
        assert alice_channel.peer_last_counter == -1
        assert not alice_channel.is_in_grace_period

    def test_reset_with_new_psk(self, alice_channel):
        """Reset with new PSK changes the key."""
        old_psk = alice_channel.psk
        new_psk = os.urandom(32)

        alice_channel.reset(new_psk=new_psk)
        assert alice_channel.psk == new_psk
        assert alice_channel.psk != old_psk


class TestPSKChannelExchangeURI:
    """Exchange URI generation."""

    def test_generate_exchange_uri(self, alice_channel):
        """Generate a valid exchange URI."""
        uri = alice_channel.generate_exchange_uri("TESTADDR", label="Test Chat")
        assert uri.startswith("algochat-psk://v1?")

        parsed = parse_psk_exchange_uri(uri)
        assert parsed["address"] == "TESTADDR"
        assert parsed["psk"] == TEST_PSK
        assert parsed["label"] == "Test Chat"

    def test_from_exchange_uri(self, alice_keys):
        """Create channel from exchange URI."""
        priv, pub = alice_keys
        psk = os.urandom(32)
        uri = f"algochat-psk://v1?addr=TESTADDR&psk={__import__('base64').urlsafe_b64encode(psk).rstrip(b'=').decode()}"

        ch = PSKChannel.from_exchange_uri(uri, priv, pub)
        assert ch.psk == psk


class TestPSKChannelCallbacks:
    """Message callback registration."""

    def test_on_message_callback(self, alice_channel, bob_channel):
        """Registered callbacks are called on decrypt."""
        received = []
        bob_channel.on_message(lambda msg: received.append(msg))

        data = alice_channel.encrypt("callback test")
        bob_channel.decrypt(data)

        assert len(received) == 1
        assert received[0].text == "callback test"

    def test_off_message_callback(self, alice_channel, bob_channel):
        """Unregistered callbacks are not called."""
        received = []
        def cb(msg):
            received.append(msg)

        bob_channel.on_message(cb)
        bob_channel.off_message(cb)

        data = alice_channel.encrypt("no callback")
        bob_channel.decrypt(data)

        assert len(received) == 0

    def test_multiple_callbacks(self, alice_channel, bob_channel):
        """Multiple callbacks all fire."""
        results1 = []
        results2 = []
        bob_channel.on_message(lambda msg: results1.append(msg.text))
        bob_channel.on_message(lambda msg: results2.append(msg.text))

        data = alice_channel.encrypt("multi")
        bob_channel.decrypt(data)

        assert results1 == ["multi"]
        assert results2 == ["multi"]


class TestPSKChannelStatePersistence:
    """State persistence and restoration."""

    def test_restore_state(self, alice_keys, bob_keys):
        """Channel can be restored from persisted state."""
        alice_priv, alice_pub = alice_keys
        bob_priv, bob_pub = bob_keys

        # Create channel and send some messages
        ch1 = PSKChannel(
            initial_psk=TEST_PSK,
            our_private_key=alice_priv,
            our_public_key=alice_pub,
            peer_public_key=bob_pub,
        )
        ch1.encrypt("msg 1")
        ch1.encrypt("msg 2")

        # Save state
        saved_state = ch1.state

        # Restore into new channel
        ch2 = PSKChannel(
            initial_psk=TEST_PSK,
            our_private_key=alice_priv,
            our_public_key=alice_pub,
            peer_public_key=bob_pub,
            state=saved_state,
        )

        assert ch2.send_counter == 2

        # New channel continues from saved counter
        bob_ch = PSKChannel(
            initial_psk=TEST_PSK,
            our_private_key=bob_priv,
            our_public_key=bob_pub,
            peer_public_key=alice_pub,
        )

        data = ch2.encrypt("msg 3")
        msg = bob_ch.decrypt(data)
        assert msg.text == "msg 3"
        assert msg.counter == 2


class TestPSKChannelPeerDiscovery:
    """Peer public key auto-discovery from first message."""

    def test_learn_peer_key_from_message(self, alice_channel, bob_keys):
        """Channel learns peer key from first received message."""
        bob_priv, bob_pub = bob_keys

        # Create Alice's channel without peer key
        ch = PSKChannel(
            initial_psk=TEST_PSK,
            our_private_key=alice_channel._our_private_key,
            our_public_key=alice_channel._our_public_key,
        )
        assert ch.peer_public_key is None

        # Bob sends a message
        bob_ch = PSKChannel(
            initial_psk=TEST_PSK,
            our_private_key=bob_priv,
            our_public_key=bob_pub,
            peer_public_key=alice_channel._our_public_key,
        )
        data = bob_ch.encrypt("discover me")

        # Alice decrypts and learns Bob's key
        msg = ch.decrypt(data)
        assert msg.text == "discover me"
        assert ch.peer_public_key is not None
        assert public_key_to_bytes(ch.peer_public_key) == public_key_to_bytes(bob_pub)
