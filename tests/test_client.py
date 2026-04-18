"""Tests for the AlgoChat client."""

import pytest
from typing import Optional

from algochat.blockchain import (
    AlgorandConfig,
    AlgodClient,
    IndexerClient,
    NoteTransaction,
    SuggestedParams,
    AccountInfo,
    TransactionInfo,
)
from algochat.client import AlgoChat, AlgoChatConfig
from algochat.keys import public_key_to_bytes
from algochat.models import MessageDirection
from algochat.storage import InMemoryKeyStorage
from algochat.types import (
    InvalidEnvelopeError,
    PublicKeyNotFoundError,
)


# ============================================================================
# Mock Blockchain Clients
# ============================================================================


class MockAlgodClient(AlgodClient):
    """Mock algod client for testing."""

    async def get_suggested_params(self) -> SuggestedParams:
        return SuggestedParams(
            fee=1000, min_fee=1000, first_valid=100, last_valid=200,
            genesis_id="testnet-v1.0", genesis_hash=b"\x00" * 32,
        )

    async def get_account_info(self, address: str) -> AccountInfo:
        return AccountInfo(address=address, amount=1_000_000, min_balance=100_000)

    async def submit_transaction(self, signed_txn: bytes) -> str:
        return "MOCK_TXID"

    async def wait_for_confirmation(self, txid: str, rounds: int) -> TransactionInfo:
        return TransactionInfo(txid=txid, confirmed_round=100)

    async def get_current_round(self) -> int:
        return 100


class MockIndexerClient(IndexerClient):
    """Mock indexer client for testing."""

    def __init__(self) -> None:
        self._transactions: list[NoteTransaction] = []

    def add_transaction(self, tx: NoteTransaction) -> None:
        self._transactions.append(tx)

    async def search_transactions(
        self, address: str, after_round: Optional[int] = None, limit: Optional[int] = None,
    ) -> list[NoteTransaction]:
        results = [tx for tx in self._transactions
                   if tx.sender == address or tx.receiver == address]
        if after_round is not None:
            results = [tx for tx in results if tx.confirmed_round > after_round]
        if limit is not None:
            results = results[:limit]
        return results

    async def search_transactions_between(
        self, address1: str, address2: str,
        after_round: Optional[int] = None, limit: Optional[int] = None,
    ) -> list[NoteTransaction]:
        results = [tx for tx in self._transactions
                   if (tx.sender == address1 and tx.receiver == address2)
                   or (tx.sender == address2 and tx.receiver == address1)]
        if after_round is not None:
            results = [tx for tx in results if tx.confirmed_round > after_round]
        if limit is not None:
            results = results[:limit]
        return results

    async def get_transaction(self, txid: str) -> NoteTransaction:
        for tx in self._transactions:
            if tx.txid == txid:
                return tx
        raise KeyError(f"Transaction {txid} not found")

    async def wait_for_indexer(self, txid: str, timeout_secs: int) -> NoteTransaction:
        return await self.get_transaction(txid)


# ============================================================================
# Helpers
# ============================================================================

ALICE_SEED = b"\x01" * 32
BOB_SEED = b"\x02" * 32
ALICE_ADDRESS = "ALICE_ADDR_000000000000000000000000000000000000000000000000000000"
BOB_ADDRESS = "BOB_ADDR_0000000000000000000000000000000000000000000000000000000"


def make_config() -> AlgoChatConfig:
    return AlgoChatConfig(network=AlgorandConfig.localnet())


async def make_client(
    seed: bytes = ALICE_SEED,
    address: str = ALICE_ADDRESS,
    config: Optional[AlgoChatConfig] = None,
    indexer: Optional[MockIndexerClient] = None,
) -> AlgoChat:
    return await AlgoChat.from_seed(
        seed=seed,
        address=address,
        config=config or make_config(),
        algod=MockAlgodClient(),
        indexer=indexer or MockIndexerClient(),
    )


# ============================================================================
# from_seed
# ============================================================================


class TestFromSeed:
    @pytest.mark.asyncio
    async def test_creates_client_with_valid_seed(self):
        client = await make_client()
        assert client.address == ALICE_ADDRESS

    @pytest.mark.asyncio
    async def test_derives_encryption_key(self):
        client = await make_client()
        # Public key should be bytes (raw X25519 public key)
        pub_key = client.encryption_public_key
        assert pub_key is not None

    @pytest.mark.asyncio
    async def test_deterministic_key_derivation(self):
        client1 = await make_client(seed=ALICE_SEED)
        client2 = await make_client(seed=ALICE_SEED)
        # Same seed → same public key
        pub1 = public_key_to_bytes(client1._encryption_public_key)
        pub2 = public_key_to_bytes(client2._encryption_public_key)
        assert pub1 == pub2

    @pytest.mark.asyncio
    async def test_different_seeds_different_keys(self):
        client1 = await make_client(seed=ALICE_SEED)
        client2 = await make_client(seed=BOB_SEED)
        pub1 = public_key_to_bytes(client1._encryption_public_key)
        pub2 = public_key_to_bytes(client2._encryption_public_key)
        assert pub1 != pub2

    @pytest.mark.asyncio
    async def test_rejects_short_seed(self):
        with pytest.raises(ValueError, match="32 bytes"):
            await make_client(seed=b"\x01" * 16)

    @pytest.mark.asyncio
    async def test_rejects_long_seed(self):
        with pytest.raises(ValueError, match="32 bytes"):
            await make_client(seed=b"\x01" * 64)

    @pytest.mark.asyncio
    async def test_stores_key_in_storage(self):
        storage = InMemoryKeyStorage()
        await AlgoChat.from_seed(
            seed=ALICE_SEED,
            address=ALICE_ADDRESS,
            config=make_config(),
            algod=MockAlgodClient(),
            indexer=MockIndexerClient(),
            key_storage=storage,
        )
        assert await storage.has_key(ALICE_ADDRESS) is True

    @pytest.mark.asyncio
    async def test_default_storage_when_none(self):
        client = await AlgoChat.from_seed(
            seed=ALICE_SEED,
            address=ALICE_ADDRESS,
            config=make_config(),
            algod=MockAlgodClient(),
            indexer=MockIndexerClient(),
        )
        # Should not raise — defaults are created
        assert client.address == ALICE_ADDRESS


# ============================================================================
# Conversations
# ============================================================================


class TestConversations:
    @pytest.mark.asyncio
    async def test_empty_conversations_initially(self):
        client = await make_client()
        convs = await client.conversations()
        assert convs == []

    @pytest.mark.asyncio
    async def test_get_or_create_conversation(self):
        client = await make_client()
        conv = await client.conversation(BOB_ADDRESS)
        assert conv.participant == BOB_ADDRESS
        assert conv.is_empty is True

    @pytest.mark.asyncio
    async def test_returns_same_conversation(self):
        client = await make_client()
        conv1 = await client.conversation(BOB_ADDRESS)
        conv2 = await client.conversation(BOB_ADDRESS)
        assert conv1 is conv2

    @pytest.mark.asyncio
    async def test_different_participants_different_conversations(self):
        client = await make_client()
        conv1 = await client.conversation(BOB_ADDRESS)
        conv2 = await client.conversation("CAROL_ADDR")
        assert conv1 is not conv2
        convs = await client.conversations()
        assert len(convs) == 2

    @pytest.mark.asyncio
    async def test_conversations_returns_copy(self):
        client = await make_client()
        await client.conversation(BOB_ADDRESS)
        convs = await client.conversations()
        convs.clear()
        # Original list should not be modified
        assert len(await client.conversations()) == 1


# ============================================================================
# Encrypt / Decrypt
# ============================================================================


class TestEncryptDecrypt:
    @pytest.mark.asyncio
    async def test_roundtrip(self):
        """Alice encrypts a message for Bob, Bob decrypts it."""
        alice = await make_client(seed=ALICE_SEED, address=ALICE_ADDRESS)
        bob = await make_client(seed=BOB_SEED, address=BOB_ADDRESS)

        alice_pub = public_key_to_bytes(alice._encryption_public_key)
        bob_pub = public_key_to_bytes(bob._encryption_public_key)

        envelope = alice.encrypt("Hello Bob!", bob_pub)
        assert isinstance(envelope, bytes)
        assert len(envelope) > 0

        plaintext = bob.decrypt(envelope, alice_pub)
        assert plaintext == "Hello Bob!"

    @pytest.mark.asyncio
    async def test_sender_can_decrypt_own_message(self):
        """Sender should be able to decrypt their own message."""
        alice = await make_client(seed=ALICE_SEED, address=ALICE_ADDRESS)
        bob = await make_client(seed=BOB_SEED, address=BOB_ADDRESS)

        bob_pub = public_key_to_bytes(bob._encryption_public_key)

        envelope = alice.encrypt("Hello Bob!", bob_pub)
        # Alice can also decrypt (sender key is encrypted in envelope)
        plaintext = alice.decrypt(envelope, bob_pub)
        assert plaintext == "Hello Bob!"

    @pytest.mark.asyncio
    async def test_decrypt_rejects_non_algochat_data(self):
        client = await make_client()
        with pytest.raises(InvalidEnvelopeError, match="Not an AlgoChat"):
            client.decrypt(b"not an envelope", b"\x00" * 32)

    @pytest.mark.asyncio
    async def test_decrypt_rejects_too_short_data(self):
        client = await make_client()
        with pytest.raises(InvalidEnvelopeError):
            client.decrypt(b"\x01\x01" + b"\x00" * 10, b"\x00" * 32)

    @pytest.mark.asyncio
    async def test_encrypt_empty_message(self):
        """Empty string should encrypt and decrypt successfully."""
        alice = await make_client(seed=ALICE_SEED, address=ALICE_ADDRESS)
        bob = await make_client(seed=BOB_SEED, address=BOB_ADDRESS)

        bob_pub = public_key_to_bytes(bob._encryption_public_key)
        alice_pub = public_key_to_bytes(alice._encryption_public_key)

        envelope = alice.encrypt("", bob_pub)
        plaintext = bob.decrypt(envelope, alice_pub)
        assert plaintext == ""

    @pytest.mark.asyncio
    async def test_encrypt_unicode_message(self):
        """Unicode messages should round-trip correctly."""
        alice = await make_client(seed=ALICE_SEED, address=ALICE_ADDRESS)
        bob = await make_client(seed=BOB_SEED, address=BOB_ADDRESS)

        bob_pub = public_key_to_bytes(bob._encryption_public_key)
        alice_pub = public_key_to_bytes(alice._encryption_public_key)

        message = "Hello 🌍 こんにちは"
        envelope = alice.encrypt(message, bob_pub)
        plaintext = bob.decrypt(envelope, alice_pub)
        assert plaintext == message


# ============================================================================
# Discover Key
# ============================================================================


class TestDiscoverKey:
    @pytest.mark.asyncio
    async def test_returns_none_when_no_key_found(self):
        client = await make_client()
        key = await client.discover_key(BOB_ADDRESS)
        assert key is None

    @pytest.mark.asyncio
    async def test_caches_discovered_key(self):
        """After discovery, second call should use cache."""
        indexer = MockIndexerClient()
        # Add a key announcement (self-transfer with 32-byte note = public key)
        indexer.add_transaction(NoteTransaction(
            txid="key-announce-1",
            sender=BOB_ADDRESS,
            receiver=BOB_ADDRESS,
            note=b"\xab" * 32,  # 32-byte key (unverified, no signature)
            confirmed_round=50,
            round_time=1700000000,
        ))

        client = await make_client(indexer=indexer)

        # First call discovers
        key1 = await client.discover_key(BOB_ADDRESS)
        assert key1 is not None
        assert key1.public_key == b"\xab" * 32

        # Remove the transaction — second call should still work (cached)
        indexer._transactions.clear()
        key2 = await client.discover_key(BOB_ADDRESS)
        assert key2 is not None
        assert key2.public_key == b"\xab" * 32

    @pytest.mark.asyncio
    async def test_skips_cache_when_disabled(self):
        indexer = MockIndexerClient()
        indexer.add_transaction(NoteTransaction(
            txid="key-announce-1",
            sender=BOB_ADDRESS,
            receiver=BOB_ADDRESS,
            note=b"\xab" * 32,
            confirmed_round=50,
            round_time=1700000000,
        ))

        config = AlgoChatConfig(network=AlgorandConfig.localnet(), cache_public_keys=False)
        client = await make_client(config=config, indexer=indexer)

        key1 = await client.discover_key(BOB_ADDRESS)
        assert key1 is not None

        # Remove transaction — without cache, should return None
        indexer._transactions.clear()
        key2 = await client.discover_key(BOB_ADDRESS)
        assert key2 is None

    @pytest.mark.asyncio
    async def test_ignores_non_self_transfers(self):
        """Key announcements must be self-transfers."""
        indexer = MockIndexerClient()
        indexer.add_transaction(NoteTransaction(
            txid="not-self-transfer",
            sender=BOB_ADDRESS,
            receiver=ALICE_ADDRESS,  # Not self-transfer
            note=b"\xab" * 32,
            confirmed_round=50,
            round_time=1700000000,
        ))

        client = await make_client(indexer=indexer)
        key = await client.discover_key(BOB_ADDRESS)
        assert key is None


# ============================================================================
# Process Transaction
# ============================================================================


class TestProcessTransaction:
    @pytest.mark.asyncio
    async def test_processes_sent_message(self):
        """Process a transaction sent by us."""
        alice = await make_client(seed=ALICE_SEED, address=ALICE_ADDRESS)
        bob = await make_client(seed=BOB_SEED, address=BOB_ADDRESS)

        bob_pub = public_key_to_bytes(bob._encryption_public_key)

        # Alice encrypts a message for Bob
        envelope = alice.encrypt("Hello Bob!", bob_pub)

        # Seed Bob's key in Alice's cache so discover_key works
        await alice.public_key_cache.store(BOB_ADDRESS, bob_pub)

        tx = NoteTransaction(
            txid="tx-1",
            sender=ALICE_ADDRESS,
            receiver=BOB_ADDRESS,
            note=envelope,
            confirmed_round=100,
            round_time=1700000000,
        )

        message = await alice.process_transaction(tx)
        assert message is not None
        assert message.id == "tx-1"
        assert message.content == "Hello Bob!"
        assert message.direction == MessageDirection.SENT

    @pytest.mark.asyncio
    async def test_processes_received_message(self):
        """Process a transaction received from someone else."""
        alice = await make_client(seed=ALICE_SEED, address=ALICE_ADDRESS)
        bob = await make_client(seed=BOB_SEED, address=BOB_ADDRESS)

        alice_pub = public_key_to_bytes(alice._encryption_public_key)
        bob_pub = public_key_to_bytes(bob._encryption_public_key)

        # Bob encrypts a message for Alice
        envelope = bob.encrypt("Hi Alice!", alice_pub)

        # Seed Bob's key in Alice's cache
        await alice.public_key_cache.store(BOB_ADDRESS, bob_pub)

        tx = NoteTransaction(
            txid="tx-2",
            sender=BOB_ADDRESS,
            receiver=ALICE_ADDRESS,
            note=envelope,
            confirmed_round=101,
            round_time=1700000001,
        )

        message = await alice.process_transaction(tx)
        assert message is not None
        assert message.id == "tx-2"
        assert message.content == "Hi Alice!"
        assert message.direction == MessageDirection.RECEIVED

    @pytest.mark.asyncio
    async def test_ignores_non_chat_messages(self):
        client = await make_client()
        tx = NoteTransaction(
            txid="tx-3",
            sender=ALICE_ADDRESS,
            receiver=BOB_ADDRESS,
            note=b"not a chat message",
            confirmed_round=100,
            round_time=1700000000,
        )
        message = await client.process_transaction(tx)
        assert message is None

    @pytest.mark.asyncio
    async def test_ignores_unrelated_transactions(self):
        """Transactions not involving our address should be ignored."""
        client = await make_client()
        tx = NoteTransaction(
            txid="tx-4",
            sender="OTHER1",
            receiver="OTHER2",
            note=b"\x01\x01" + b"\x00" * 200,  # Looks like chat but not for us
            confirmed_round=100,
            round_time=1700000000,
        )
        message = await client.process_transaction(tx)
        assert message is None

    @pytest.mark.asyncio
    async def test_creates_conversation_on_new_participant(self):
        """Processing a transaction should create a conversation if needed."""
        alice = await make_client(seed=ALICE_SEED, address=ALICE_ADDRESS)
        bob = await make_client(seed=BOB_SEED, address=BOB_ADDRESS)

        bob_pub = public_key_to_bytes(bob._encryption_public_key)
        alice_pub = public_key_to_bytes(alice._encryption_public_key)

        envelope = bob.encrypt("First contact!", alice_pub)
        await alice.public_key_cache.store(BOB_ADDRESS, bob_pub)

        assert len(await alice.conversations()) == 0

        tx = NoteTransaction(
            txid="tx-5",
            sender=BOB_ADDRESS,
            receiver=ALICE_ADDRESS,
            note=envelope,
            confirmed_round=100,
            round_time=1700000000,
        )
        await alice.process_transaction(tx)

        convs = await alice.conversations()
        assert len(convs) == 1
        assert convs[0].participant == BOB_ADDRESS
        assert convs[0].message_count == 1

    @pytest.mark.asyncio
    async def test_appends_to_existing_conversation(self):
        """Multiple messages to same participant should go in same conversation."""
        alice = await make_client(seed=ALICE_SEED, address=ALICE_ADDRESS)
        bob = await make_client(seed=BOB_SEED, address=BOB_ADDRESS)

        bob_pub = public_key_to_bytes(bob._encryption_public_key)
        alice_pub = public_key_to_bytes(alice._encryption_public_key)
        await alice.public_key_cache.store(BOB_ADDRESS, bob_pub)

        for i in range(3):
            envelope = bob.encrypt(f"Message {i}", alice_pub)
            tx = NoteTransaction(
                txid=f"tx-{i}",
                sender=BOB_ADDRESS,
                receiver=ALICE_ADDRESS,
                note=envelope,
                confirmed_round=100 + i,
                round_time=1700000000 + i,
            )
            await alice.process_transaction(tx)

        convs = await alice.conversations()
        assert len(convs) == 1
        assert convs[0].message_count == 3

    @pytest.mark.asyncio
    async def test_caches_messages(self):
        """Messages should be stored in the message cache."""
        alice = await make_client(seed=ALICE_SEED, address=ALICE_ADDRESS)
        bob = await make_client(seed=BOB_SEED, address=BOB_ADDRESS)

        bob_pub = public_key_to_bytes(bob._encryption_public_key)
        alice_pub = public_key_to_bytes(alice._encryption_public_key)
        await alice.public_key_cache.store(BOB_ADDRESS, bob_pub)

        envelope = bob.encrypt("Cached msg", alice_pub)
        tx = NoteTransaction(
            txid="tx-cache",
            sender=BOB_ADDRESS,
            receiver=ALICE_ADDRESS,
            note=envelope,
            confirmed_round=100,
            round_time=1700000000,
        )
        await alice.process_transaction(tx)

        # Check cache
        cached = await alice.message_cache.retrieve(BOB_ADDRESS)
        assert len(cached) == 1
        assert cached[0].content == "Cached msg"

    @pytest.mark.asyncio
    async def test_raises_when_key_not_found(self):
        """Should raise PublicKeyNotFoundError when recipient key is missing."""
        alice = await make_client(seed=ALICE_SEED, address=ALICE_ADDRESS)
        bob = await make_client(seed=BOB_SEED, address=BOB_ADDRESS)

        # Don't cache Bob's key — discovery will also fail (empty indexer)

        envelope = bob.encrypt("No key!", public_key_to_bytes(alice._encryption_public_key))
        tx = NoteTransaction(
            txid="tx-nokey",
            sender=BOB_ADDRESS,
            receiver=ALICE_ADDRESS,
            note=envelope,
            confirmed_round=100,
            round_time=1700000000,
        )

        with pytest.raises(PublicKeyNotFoundError):
            await alice.process_transaction(tx)


# ============================================================================
# Sync
# ============================================================================


class TestSync:
    @pytest.mark.asyncio
    async def test_sync_returns_messages(self):
        """Sync should process blockchain transactions and return messages."""
        indexer = MockIndexerClient()
        alice = await make_client(seed=ALICE_SEED, address=ALICE_ADDRESS, indexer=indexer)
        bob = await make_client(seed=BOB_SEED, address=BOB_ADDRESS)

        alice_pub = public_key_to_bytes(alice._encryption_public_key)
        bob_pub = public_key_to_bytes(bob._encryption_public_key)
        await alice.public_key_cache.store(BOB_ADDRESS, bob_pub)

        envelope = bob.encrypt("Synced message", alice_pub)
        indexer.add_transaction(NoteTransaction(
            txid="sync-tx-1",
            sender=BOB_ADDRESS,
            receiver=ALICE_ADDRESS,
            note=envelope,
            confirmed_round=100,
            round_time=1700000000,
        ))

        messages = await alice.sync()
        assert len(messages) == 1
        assert messages[0].content == "Synced message"
        assert messages[0].direction == MessageDirection.RECEIVED

    @pytest.mark.asyncio
    async def test_sync_skips_non_chat_transactions(self):
        """Non-chat transactions should be silently skipped."""
        indexer = MockIndexerClient()
        client = await make_client(indexer=indexer)

        indexer.add_transaction(NoteTransaction(
            txid="payment-tx",
            sender=BOB_ADDRESS,
            receiver=ALICE_ADDRESS,
            note=b"just a payment note",
            confirmed_round=100,
            round_time=1700000000,
        ))

        messages = await client.sync()
        assert messages == []

    @pytest.mark.asyncio
    async def test_sync_empty_blockchain(self):
        """Sync with no transactions should return empty list."""
        client = await make_client()
        messages = await client.sync()
        assert messages == []


# ============================================================================
# Properties
# ============================================================================


class TestProperties:
    @pytest.mark.asyncio
    async def test_address_property(self):
        client = await make_client(address="MY_ADDR")
        assert client.address == "MY_ADDR"

    @pytest.mark.asyncio
    async def test_send_queue_property(self):
        client = await make_client()
        queue = client.send_queue
        assert queue is not None

    @pytest.mark.asyncio
    async def test_message_cache_property(self):
        client = await make_client()
        cache = client.message_cache
        assert cache is not None

    @pytest.mark.asyncio
    async def test_public_key_cache_property(self):
        client = await make_client()
        cache = client.public_key_cache
        assert cache is not None


# ============================================================================
# Config
# ============================================================================


class TestAlgoChatConfig:
    def test_localnet_config(self):
        config = AlgoChatConfig.localnet()
        assert config.network.algod_url == "http://localhost:4001"
        assert config.auto_discover_keys is True
        assert config.cache_public_keys is True
        assert config.cache_messages is True

    def test_testnet_config(self):
        config = AlgoChatConfig.testnet()
        assert "testnet" in config.network.algod_url

    def test_mainnet_config(self):
        config = AlgoChatConfig.mainnet()
        assert "mainnet" in config.network.algod_url

    def test_custom_config(self):
        config = AlgoChatConfig(
            network=AlgorandConfig.localnet(),
            auto_discover_keys=False,
            cache_public_keys=False,
            cache_messages=False,
        )
        assert config.auto_discover_keys is False
        assert config.cache_public_keys is False
        assert config.cache_messages is False


# =====================================================================
