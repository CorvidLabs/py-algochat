"""Tests for PSK integration in the AlgoChat client."""

import os
import pytest
import pytest_asyncio
from datetime import datetime
from unittest.mock import AsyncMock

from algochat.client import AlgoChat, AlgoChatConfig
from algochat.blockchain import AlgorandConfig, NoteTransaction
from algochat.keys import derive_keys_from_seed, public_key_to_bytes
from algochat.models import PSKContact, MessageDirection
from algochat.psk_envelope import is_psk_message
from algochat.envelope import is_chat_message
from algochat.types import PSKEncryptionError, PSKDecryptionError


# Test seeds (deterministic)
ALICE_SEED = bytes([0] * 31 + [1])
BOB_SEED = bytes([0] * 31 + [2])
TEST_PSK = bytes(range(32))


def make_mock_algod():
    mock = AsyncMock()
    return mock


def make_mock_indexer():
    mock = AsyncMock()
    return mock


@pytest_asyncio.fixture
async def alice():
    config = AlgoChatConfig(network=AlgorandConfig.testnet())
    client = await AlgoChat.from_seed(
        seed=ALICE_SEED,
        address="ALICE_ADDRESS",
        config=config,
        algod=make_mock_algod(),
        indexer=make_mock_indexer(),
    )
    return client


@pytest_asyncio.fixture
async def bob():
    config = AlgoChatConfig(network=AlgorandConfig.testnet())
    client = await AlgoChat.from_seed(
        seed=BOB_SEED,
        address="BOB_ADDRESS",
        config=config,
        algod=make_mock_algod(),
        indexer=make_mock_indexer(),
    )
    return client


class TestPSKContactManagement:
    """Tests for PSK contact CRUD operations."""

    @pytest.mark.asyncio
    async def test_add_psk_contact(self, alice):
        contact = alice.add_psk_contact("BOB_ADDRESS", TEST_PSK, label="Bob")

        assert contact.address == "BOB_ADDRESS"
        assert contact.initial_psk == TEST_PSK
        assert contact.label == "Bob"
        assert contact.send_counter == 0
        assert contact.peer_last_counter == -1
        assert contact.seen_counters == set()

    @pytest.mark.asyncio
    async def test_add_psk_contact_invalid_psk_length(self, alice):
        with pytest.raises(ValueError, match="PSK must be 32 bytes"):
            alice.add_psk_contact("BOB_ADDRESS", b"too_short")

    @pytest.mark.asyncio
    async def test_get_psk_contact(self, alice):
        alice.add_psk_contact("BOB_ADDRESS", TEST_PSK)

        contact = alice.get_psk_contact("BOB_ADDRESS")
        assert contact is not None
        assert contact.address == "BOB_ADDRESS"

    @pytest.mark.asyncio
    async def test_get_psk_contact_not_found(self, alice):
        assert alice.get_psk_contact("UNKNOWN") is None

    @pytest.mark.asyncio
    async def test_remove_psk_contact(self, alice):
        alice.add_psk_contact("BOB_ADDRESS", TEST_PSK)
        assert alice.remove_psk_contact("BOB_ADDRESS") is True
        assert alice.get_psk_contact("BOB_ADDRESS") is None

    @pytest.mark.asyncio
    async def test_remove_psk_contact_not_found(self, alice):
        assert alice.remove_psk_contact("UNKNOWN") is False

    @pytest.mark.asyncio
    async def test_psk_contacts_property(self, alice):
        alice.add_psk_contact("BOB_ADDRESS", TEST_PSK, label="Bob")
        alice.add_psk_contact("CAROL_ADDRESS", os.urandom(32), label="Carol")

        contacts = alice.psk_contacts
        assert len(contacts) == 2
        addresses = {c.address for c in contacts}
        assert addresses == {"BOB_ADDRESS", "CAROL_ADDRESS"}

    @pytest.mark.asyncio
    async def test_add_psk_contact_from_uri(self, alice):
        uri = "algochat-psk://v1?addr=BOB_ADDRESS&psk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&label=Bob"
        contact = alice.add_psk_contact_from_uri(uri)

        assert contact.address == "BOB_ADDRESS"
        assert len(contact.initial_psk) == 32
        assert contact.label == "Bob"

    @pytest.mark.asyncio
    async def test_create_psk_exchange_uri(self, alice):
        uri = alice.create_psk_exchange_uri(TEST_PSK, label="Alice")
        assert uri.startswith("algochat-psk://v1?")
        assert "addr=ALICE_ADDRESS" in uri
        assert "label=Alice" in uri


class TestPSKEncryptDecrypt:
    """Tests for PSK encrypt/decrypt through the client."""

    @pytest.mark.asyncio
    async def test_encrypt_psk_produces_psk_envelope(self, alice, bob):
        alice.add_psk_contact("BOB_ADDRESS", TEST_PSK)

        bob_pub_bytes = public_key_to_bytes(bob._encryption_public_key)
        encrypted = alice.encrypt_psk("Hello PSK!", "BOB_ADDRESS", bob_pub_bytes)

        assert is_psk_message(encrypted)
        assert not is_chat_message(encrypted)

    @pytest.mark.asyncio
    async def test_encrypt_psk_no_contact_raises(self, alice, bob):
        bob_pub_bytes = public_key_to_bytes(bob._encryption_public_key)

        with pytest.raises(PSKEncryptionError, match="No PSK contact"):
            alice.encrypt_psk("Hello", "BOB_ADDRESS", bob_pub_bytes)

    @pytest.mark.asyncio
    async def test_psk_roundtrip(self, alice, bob):
        alice.add_psk_contact("BOB_ADDRESS", TEST_PSK)
        bob.add_psk_contact("ALICE_ADDRESS", TEST_PSK)

        bob_pub_bytes = public_key_to_bytes(bob._encryption_public_key)
        encrypted = alice.encrypt_psk("Hello PSK!", "BOB_ADDRESS", bob_pub_bytes)

        decrypted = bob.decrypt_psk(encrypted, "ALICE_ADDRESS")
        assert decrypted == "Hello PSK!"

    @pytest.mark.asyncio
    async def test_psk_bidirectional_decryption(self, alice, bob):
        """Sender can decrypt their own PSK messages."""
        alice.add_psk_contact("BOB_ADDRESS", TEST_PSK)

        bob_pub_bytes = public_key_to_bytes(bob._encryption_public_key)
        encrypted = alice.encrypt_psk("Hello PSK!", "BOB_ADDRESS", bob_pub_bytes)

        # Alice should be able to decrypt her own message
        decrypted = alice.decrypt_psk(encrypted, "BOB_ADDRESS")
        assert decrypted == "Hello PSK!"

    @pytest.mark.asyncio
    async def test_psk_counter_advances(self, alice, bob):
        alice.add_psk_contact("BOB_ADDRESS", TEST_PSK)
        bob.add_psk_contact("ALICE_ADDRESS", TEST_PSK)

        bob_pub_bytes = public_key_to_bytes(bob._encryption_public_key)

        # Send 3 messages
        for i in range(3):
            encrypted = alice.encrypt_psk(f"Message {i}", "BOB_ADDRESS", bob_pub_bytes)
            decrypted = bob.decrypt_psk(encrypted, "ALICE_ADDRESS")
            assert decrypted == f"Message {i}"

        # Alice's send counter should be 3
        alice_contact = alice.get_psk_contact("BOB_ADDRESS")
        assert alice_contact.send_counter == 3

        # Bob's peer_last_counter should be 2 (0-indexed)
        bob_contact = bob.get_psk_contact("ALICE_ADDRESS")
        assert bob_contact.peer_last_counter == 2

    @pytest.mark.asyncio
    async def test_psk_replay_protection(self, alice, bob):
        """Same message cannot be decrypted twice (replay attack)."""
        alice.add_psk_contact("BOB_ADDRESS", TEST_PSK)
        bob.add_psk_contact("ALICE_ADDRESS", TEST_PSK)

        bob_pub_bytes = public_key_to_bytes(bob._encryption_public_key)
        encrypted = alice.encrypt_psk("Hello!", "BOB_ADDRESS", bob_pub_bytes)

        # First decrypt succeeds
        bob.decrypt_psk(encrypted, "ALICE_ADDRESS")

        # Second decrypt of same message fails (replay)
        with pytest.raises(PSKDecryptionError, match="Invalid ratchet counter"):
            bob.decrypt_psk(encrypted, "ALICE_ADDRESS")

    @pytest.mark.asyncio
    async def test_psk_decrypt_no_contact_raises(self, alice, bob):
        alice.add_psk_contact("BOB_ADDRESS", TEST_PSK)

        bob_pub_bytes = public_key_to_bytes(bob._encryption_public_key)
        encrypted = alice.encrypt_psk("Hello!", "BOB_ADDRESS", bob_pub_bytes)

        # Bob has no PSK contact for Alice
        with pytest.raises(PSKDecryptionError, match="No PSK contact"):
            bob.decrypt_psk(encrypted, "ALICE_ADDRESS")

    @pytest.mark.asyncio
    async def test_psk_out_of_order_delivery(self, alice, bob):
        """Messages received out of order should still decrypt."""
        alice.add_psk_contact("BOB_ADDRESS", TEST_PSK)
        bob.add_psk_contact("ALICE_ADDRESS", TEST_PSK)

        bob_pub_bytes = public_key_to_bytes(bob._encryption_public_key)

        # Send 3 messages
        messages = []
        for i in range(3):
            encrypted = alice.encrypt_psk(f"Message {i}", "BOB_ADDRESS", bob_pub_bytes)
            messages.append(encrypted)

        # Receive out of order: 2, 0, 1
        assert bob.decrypt_psk(messages[2], "ALICE_ADDRESS") == "Message 2"
        assert bob.decrypt_psk(messages[0], "ALICE_ADDRESS") == "Message 0"
        assert bob.decrypt_psk(messages[1], "ALICE_ADDRESS") == "Message 1"

    @pytest.mark.asyncio
    async def test_psk_multi_message_conversation(self, alice, bob):
        """Both parties can send PSK messages back and forth."""
        alice.add_psk_contact("BOB_ADDRESS", TEST_PSK)
        bob.add_psk_contact("ALICE_ADDRESS", TEST_PSK)

        alice_pub_bytes = public_key_to_bytes(alice._encryption_public_key)
        bob_pub_bytes = public_key_to_bytes(bob._encryption_public_key)

        # Alice -> Bob
        enc1 = alice.encrypt_psk("Hi Bob!", "BOB_ADDRESS", bob_pub_bytes)
        assert bob.decrypt_psk(enc1, "ALICE_ADDRESS") == "Hi Bob!"

        # Bob -> Alice
        enc2 = bob.encrypt_psk("Hi Alice!", "ALICE_ADDRESS", alice_pub_bytes)
        assert alice.decrypt_psk(enc2, "BOB_ADDRESS") == "Hi Alice!"

        # Alice -> Bob again
        enc3 = alice.encrypt_psk("How are you?", "BOB_ADDRESS", bob_pub_bytes)
        assert bob.decrypt_psk(enc3, "ALICE_ADDRESS") == "How are you?"


class TestProcessTransactionPSK:
    """Tests for process_transaction with PSK messages."""

    @pytest.mark.asyncio
    async def test_process_psk_transaction_received(self, alice, bob):
        """process_transaction handles incoming PSK messages."""
        alice.add_psk_contact("BOB_ADDRESS", TEST_PSK)
        bob.add_psk_contact("ALICE_ADDRESS", TEST_PSK)

        # Alice encrypts a message for Bob
        bob_pub_bytes = public_key_to_bytes(bob._encryption_public_key)
        encrypted = alice.encrypt_psk("Hello from tx!", "BOB_ADDRESS", bob_pub_bytes)

        # Create a mock transaction
        tx = NoteTransaction(
            txid="TX123",
            sender="ALICE_ADDRESS",
            receiver="BOB_ADDRESS",
            note=encrypted,
            confirmed_round=1000,
            round_time=int(datetime.now().timestamp()),
        )

        message = await bob.process_transaction(tx)

        assert message is not None
        assert message.content == "Hello from tx!"
        assert message.direction == MessageDirection.RECEIVED
        assert message.sender == "ALICE_ADDRESS"
        assert message.recipient == "BOB_ADDRESS"

    @pytest.mark.asyncio
    async def test_process_psk_transaction_sent(self, alice, bob):
        """process_transaction handles own PSK messages (bidirectional)."""
        alice.add_psk_contact("BOB_ADDRESS", TEST_PSK)

        bob_pub_bytes = public_key_to_bytes(bob._encryption_public_key)
        encrypted = alice.encrypt_psk("My sent msg", "BOB_ADDRESS", bob_pub_bytes)

        tx = NoteTransaction(
            txid="TX456",
            sender="ALICE_ADDRESS",
            receiver="BOB_ADDRESS",
            note=encrypted,
            confirmed_round=1001,
            round_time=int(datetime.now().timestamp()),
        )

        message = await alice.process_transaction(tx)

        assert message is not None
        assert message.content == "My sent msg"
        assert message.direction == MessageDirection.SENT

    @pytest.mark.asyncio
    async def test_process_standard_transaction_still_works(self, alice, bob):
        """process_transaction still handles standard protocol messages."""
        # Encrypt standard message
        bob_pub_bytes = public_key_to_bytes(bob._encryption_public_key)
        encrypted = alice.encrypt("Standard hello", bob_pub_bytes)

        assert is_chat_message(encrypted)
        assert not is_psk_message(encrypted)

        # Mock discover_key for Bob to find Alice's key
        alice_pub_bytes = public_key_to_bytes(alice._encryption_public_key)
        from algochat.models import DiscoveredKey
        bob._indexer.search_transactions = AsyncMock(return_value=[])

        # Pre-populate cache
        await bob._public_key_cache.store("ALICE_ADDRESS", alice_pub_bytes)

        tx = NoteTransaction(
            txid="TX789",
            sender="ALICE_ADDRESS",
            receiver="BOB_ADDRESS",
            note=encrypted,
            confirmed_round=1002,
            round_time=int(datetime.now().timestamp()),
        )

        message = await bob.process_transaction(tx)

        assert message is not None
        assert message.content == "Standard hello"

    @pytest.mark.asyncio
    async def test_process_non_chat_transaction_returns_none(self, alice):
        """Non-chat transactions are ignored."""
        tx = NoteTransaction(
            txid="TX000",
            sender="SOMEONE",
            receiver="ALICE_ADDRESS",
            note=b"not a chat message",
            confirmed_round=1003,
            round_time=int(datetime.now().timestamp()),
        )

        assert await alice.process_transaction(tx) is None


class TestPSKContactModel:
    """Tests for the PSKContact dataclass."""

    def test_psk_contact_defaults(self):
        contact = PSKContact(address="ADDR", initial_psk=TEST_PSK)
        assert contact.send_counter == 0
        assert contact.peer_last_counter == -1
        assert contact.seen_counters == set()
        assert contact.label is None

    def test_psk_contact_with_label(self):
        contact = PSKContact(address="ADDR", initial_psk=TEST_PSK, label="Test")
        assert contact.label == "Test"
