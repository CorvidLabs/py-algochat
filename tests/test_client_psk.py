"""Tests for PSK v1.1 client integration."""

import pytest

from algochat.keys import derive_keys_from_seed, public_key_to_bytes
from algochat.psk_envelope import is_psk_message
from algochat.psk_state import PSKState
from algochat.types import InvalidEnvelopeError, PSKDecryptionError

from .test_vectors import ALICE_SEED_HEX, BOB_SEED_HEX

# Test PSK (32 bytes)
TEST_PSK = bytes([0xAA] * 32)

# Derive key pairs for Alice and Bob
ALICE_SEED = bytes.fromhex(ALICE_SEED_HEX)
BOB_SEED = bytes.fromhex(BOB_SEED_HEX)
ALICE_PRIV, ALICE_PUB = derive_keys_from_seed(ALICE_SEED)
BOB_PRIV, BOB_PUB = derive_keys_from_seed(BOB_SEED)
ALICE_PUB_BYTES = public_key_to_bytes(ALICE_PUB)
BOB_PUB_BYTES = public_key_to_bytes(BOB_PUB)


class MockAlgodClient:
    pass


class MockIndexerClient:
    async def search_transactions(self, address, limit=100):
        return []


class MockKeyStorage:
    def __init__(self):
        self._keys = {}

    async def store(self, private_key, address, require_biometric=False):
        self._keys[address] = private_key

    async def retrieve(self, address):
        return self._keys.get(address)

    async def has_key(self, address):
        return address in self._keys

    async def delete(self, address):
        self._keys.pop(address, None)

    async def list_stored_addresses(self):
        return list(self._keys.keys())


class MockMessageCache:
    def __init__(self):
        self._messages = {}

    async def store(self, messages, participant):
        self._messages.setdefault(participant, []).extend(messages)

    async def retrieve(self, participant, after_round=None):
        return self._messages.get(participant, [])

    async def get_last_sync_round(self, participant):
        return None

    async def set_last_sync_round(self, round, participant):
        pass

    async def get_cached_conversations(self):
        return list(self._messages.keys())

    async def clear(self):
        self._messages.clear()

    async def clear_for(self, participant):
        self._messages.pop(participant, None)


def make_config():
    from algochat.client import AlgoChatConfig
    from algochat.blockchain import AlgorandConfig

    return AlgoChatConfig(network=AlgorandConfig.localnet())


def make_alice():
    from algochat.client import AlgoChat
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    ed25519_private = Ed25519PrivateKey.from_private_bytes(ALICE_SEED)
    ed25519_pub = ed25519_private.public_key().public_bytes_raw()

    return AlgoChat(
        address="ALICE_ADDRESS",
        ed25519_public_key=ed25519_pub,
        encryption_private_key=ALICE_PRIV,
        encryption_public_key=ALICE_PUB,
        config=make_config(),
        algod=MockAlgodClient(),
        indexer=MockIndexerClient(),
        key_storage=MockKeyStorage(),
        message_cache=MockMessageCache(),
    )


def make_bob():
    from algochat.client import AlgoChat
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    ed25519_private = Ed25519PrivateKey.from_private_bytes(BOB_SEED)
    ed25519_pub = ed25519_private.public_key().public_bytes_raw()

    return AlgoChat(
        address="BOB_ADDRESS",
        ed25519_public_key=ed25519_pub,
        encryption_private_key=BOB_PRIV,
        encryption_public_key=BOB_PUB,
        config=make_config(),
        algod=MockAlgodClient(),
        indexer=MockIndexerClient(),
        key_storage=MockKeyStorage(),
        message_cache=MockMessageCache(),
    )


class TestAddPSKContact:
    """Tests for add_psk_contact."""

    @pytest.mark.asyncio
    async def test_creates_psk_conversation(self):
        alice = make_alice()
        conv = await alice.add_psk_contact("BOB_ADDRESS", TEST_PSK, label="Bob")

        assert conv.participant == "BOB_ADDRESS"
        assert conv.psk == TEST_PSK
        assert conv.psk_label == "Bob"
        assert conv.is_psk_enabled
        assert conv.psk_state is not None
        assert conv.psk_state.send_counter == 0

    @pytest.mark.asyncio
    async def test_rejects_invalid_psk_length(self):
        alice = make_alice()
        with pytest.raises(ValueError, match="PSK must be 32 bytes"):
            await alice.add_psk_contact("BOB_ADDRESS", b"too_short")

    @pytest.mark.asyncio
    async def test_updates_existing_conversation(self):
        alice = make_alice()
        conv1 = await alice.conversation("BOB_ADDRESS")
        assert not conv1.is_psk_enabled

        conv2 = await alice.add_psk_contact("BOB_ADDRESS", TEST_PSK)
        assert conv1 is conv2  # Same object
        assert conv1.is_psk_enabled


class TestEncryptDecryptPSK:
    """Tests for low-level encrypt_psk / decrypt_psk."""

    def test_round_trip_as_recipient(self):
        alice = make_alice()
        bob = make_bob()

        encrypted = alice.encrypt_psk("Hello Bob!", BOB_PUB_BYTES, TEST_PSK, counter=0)

        assert is_psk_message(encrypted)

        decrypted = bob.decrypt_psk(encrypted, TEST_PSK)
        assert decrypted is not None
        assert decrypted.text == "Hello Bob!"

    def test_round_trip_as_sender(self):
        alice = make_alice()

        encrypted = alice.encrypt_psk("Hello!", BOB_PUB_BYTES, TEST_PSK, counter=0)
        decrypted = alice.decrypt_psk(encrypted, TEST_PSK)
        assert decrypted is not None
        assert decrypted.text == "Hello!"

    def test_different_counters(self):
        alice = make_alice()
        bob = make_bob()

        enc0 = alice.encrypt_psk("msg0", BOB_PUB_BYTES, TEST_PSK, counter=0)
        enc1 = alice.encrypt_psk("msg1", BOB_PUB_BYTES, TEST_PSK, counter=1)

        # Different counters produce different ciphertext
        assert enc0 != enc1

        result0 = bob.decrypt_psk(enc0, TEST_PSK)
        result1 = bob.decrypt_psk(enc1, TEST_PSK)
        assert result0 is not None and result0.text == "msg0"
        assert result1 is not None and result1.text == "msg1"

    def test_unicode_message(self):
        alice = make_alice()
        bob = make_bob()

        encrypted = alice.encrypt_psk("こんにちは 👋", BOB_PUB_BYTES, TEST_PSK, counter=0)
        result = bob.decrypt_psk(encrypted, TEST_PSK)
        assert result is not None and result.text == "こんにちは 👋"

    def test_decrypt_non_psk_raises(self):
        alice = make_alice()
        with pytest.raises(InvalidEnvelopeError, match="Not a PSK message"):
            alice.decrypt_psk(b"\x01\x01" + b"\x00" * 200, TEST_PSK)

    def test_wrong_psk_fails(self):
        alice = make_alice()
        bob = make_bob()

        encrypted = alice.encrypt_psk("secret", BOB_PUB_BYTES, TEST_PSK, counter=0)

        wrong_psk = bytes([0xBB] * 32)
        with pytest.raises(Exception):
            bob.decrypt_psk(encrypted, wrong_psk)


class TestSendReceivePSK:
    """Tests for high-level send_psk / receive_psk with state management."""

    @pytest.mark.asyncio
    async def test_send_advances_counter(self):
        alice = make_alice()
        await alice.add_psk_contact("BOB_ADDRESS", TEST_PSK)

        # Mock key discovery
        from algochat.models import DiscoveredKey

        async def mock_discover(addr):
            return DiscoveredKey(public_key=BOB_PUB_BYTES, is_verified=True)

        alice.discover_key = mock_discover

        _, counter0 = await alice.send_psk("BOB_ADDRESS", "msg0")
        _, counter1 = await alice.send_psk("BOB_ADDRESS", "msg1")
        _, counter2 = await alice.send_psk("BOB_ADDRESS", "msg2")

        assert counter0 == 0
        assert counter1 == 1
        assert counter2 == 2

        conv = await alice.conversation("BOB_ADDRESS")
        assert conv.psk_state.send_counter == 3

    @pytest.mark.asyncio
    async def test_send_without_psk_raises(self):
        alice = make_alice()
        with pytest.raises(ValueError, match="No PSK configured"):
            await alice.send_psk("BOB_ADDRESS", "hello")

    @pytest.mark.asyncio
    async def test_receive_updates_counter_state(self):
        alice = make_alice()
        bob = make_bob()

        await alice.add_psk_contact("BOB_ADDRESS", TEST_PSK)
        await bob.add_psk_contact("ALICE_ADDRESS", TEST_PSK)

        # Alice encrypts manually (simulating send)
        encrypted = alice.encrypt_psk("Hello!", BOB_PUB_BYTES, TEST_PSK, counter=0)

        # Bob receives via high-level API
        result = await bob.receive_psk(encrypted, "ALICE_ADDRESS")
        assert result is not None
        assert result.text == "Hello!"

        # Counter state should be updated
        conv = await bob.conversation("ALICE_ADDRESS")
        assert conv.psk_state.peer_last_counter == 0
        assert 0 in conv.psk_state.seen_counters

    @pytest.mark.asyncio
    async def test_receive_rejects_replay(self):
        alice = make_alice()
        bob = make_bob()

        await alice.add_psk_contact("BOB_ADDRESS", TEST_PSK)
        await bob.add_psk_contact("ALICE_ADDRESS", TEST_PSK)

        encrypted = alice.encrypt_psk("Hello!", BOB_PUB_BYTES, TEST_PSK, counter=0)

        # First receive succeeds
        await bob.receive_psk(encrypted, "ALICE_ADDRESS")

        # Replay is rejected
        with pytest.raises(PSKDecryptionError, match="replay or out of window"):
            await bob.receive_psk(encrypted, "ALICE_ADDRESS")

    @pytest.mark.asyncio
    async def test_receive_without_psk_raises(self):
        bob = make_bob()
        with pytest.raises(ValueError, match="No PSK configured"):
            await bob.receive_psk(b"\x01\x02" + b"\x00" * 200, "ALICE_ADDRESS")

    @pytest.mark.asyncio
    async def test_full_conversation(self):
        """Simulate a back-and-forth PSK conversation."""
        alice = make_alice()
        bob = make_bob()

        await alice.add_psk_contact("BOB_ADDRESS", TEST_PSK)
        await bob.add_psk_contact("ALICE_ADDRESS", TEST_PSK)

        from algochat.models import DiscoveredKey

        async def alice_discover(addr):
            return DiscoveredKey(public_key=BOB_PUB_BYTES, is_verified=True)

        async def bob_discover(addr):
            return DiscoveredKey(public_key=ALICE_PUB_BYTES, is_verified=True)

        alice.discover_key = alice_discover
        bob.discover_key = bob_discover

        # Alice sends to Bob
        enc1, _ = await alice.send_psk("BOB_ADDRESS", "Hey Bob!")
        result1 = await bob.receive_psk(enc1, "ALICE_ADDRESS")
        assert result1 is not None and result1.text == "Hey Bob!"

        # Bob sends to Alice
        enc2, _ = await bob.send_psk("ALICE_ADDRESS", "Hi Alice!")
        result2 = await alice.receive_psk(enc2, "BOB_ADDRESS")
        assert result2 is not None and result2.text == "Hi Alice!"

        # Alice sends again (counter advances)
        enc3, counter3 = await alice.send_psk("BOB_ADDRESS", "How are you?")
        assert counter3 == 1  # Second message from Alice
        result3 = await bob.receive_psk(enc3, "ALICE_ADDRESS")
        assert result3 is not None and result3.text == "How are you?"


class TestConversationPSKProperties:
    """Tests for Conversation model PSK fields."""

    def test_default_no_psk(self):
        from algochat.models import Conversation

        conv = Conversation("ADDR")
        assert not conv.is_psk_enabled
        assert conv.psk is None
        assert conv.psk_state is None
        assert conv.psk_label is None

    def test_psk_enabled(self):
        from algochat.models import Conversation

        conv = Conversation("ADDR", psk=TEST_PSK, psk_state=PSKState(), psk_label="Test")
        assert conv.is_psk_enabled
        assert conv.psk == TEST_PSK
        assert conv.psk_state.send_counter == 0
        assert conv.psk_label == "Test"
