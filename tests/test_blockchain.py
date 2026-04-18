"""Tests for blockchain interfaces and key discovery."""

import pytest
from typing import Optional

from algochat.blockchain import (
    AlgorandConfig,
    IndexerClient,
    NoteTransaction,
    SuggestedParams,
    AccountInfo,
    TransactionInfo,
    _decode_algorand_address,
    _parse_key_announcement,
    discover_encryption_key,
)
from algochat.keys import derive_keys_from_seed, public_key_to_bytes
from algochat.signature import sign_encryption_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# ============================================================================
# Mock Indexer
# ============================================================================


class MockIndexerClient(IndexerClient):
    """Mock indexer for testing key discovery."""

    def __init__(self) -> None:
        self._transactions: list[NoteTransaction] = []

    def add_transaction(self, tx: NoteTransaction) -> None:
        self._transactions.append(tx)

    async def search_transactions(
        self, address: str, after_round: Optional[int] = None, limit: Optional[int] = None,
    ) -> list[NoteTransaction]:
        results = [tx for tx in self._transactions
                   if tx.sender == address or tx.receiver == address]
        if limit is not None:
            results = results[:limit]
        return results

    async def search_transactions_between(
        self, address1: str, address2: str,
        after_round: Optional[int] = None, limit: Optional[int] = None,
    ) -> list[NoteTransaction]:
        return []

    async def get_transaction(self, txid: str) -> NoteTransaction:
        for tx in self._transactions:
            if tx.txid == txid:
                return tx
        raise KeyError(f"Transaction {txid} not found")

    async def wait_for_indexer(self, txid: str, timeout_secs: int) -> NoteTransaction:
        return await self.get_transaction(txid)


# ============================================================================
# AlgorandConfig
# ============================================================================


class TestAlgorandConfig:
    def test_localnet(self):
        config = AlgorandConfig.localnet()
        assert config.algod_url == "http://localhost:4001"
        assert config.algod_token == "a" * 64
        assert config.indexer_url == "http://localhost:8980"
        assert config.indexer_token == "a" * 64

    def test_testnet(self):
        config = AlgorandConfig.testnet()
        assert "testnet" in config.algod_url
        assert "testnet" in config.indexer_url
        assert config.algod_token == ""

    def test_mainnet(self):
        config = AlgorandConfig.mainnet()
        assert "mainnet" in config.algod_url
        assert "mainnet" in config.indexer_url

    def test_with_indexer(self):
        config = AlgorandConfig.localnet().with_indexer("http://custom:9000", "token123")
        assert config.indexer_url == "http://custom:9000"
        assert config.indexer_token == "token123"
        # Original algod settings preserved
        assert config.algod_url == "http://localhost:4001"


# ============================================================================
# _decode_algorand_address
# ============================================================================


class TestDecodeAlgorandAddress:
    def test_returns_32_bytes(self):
        # A valid Algorand address is 58 chars (base32 of 36 bytes: 32 key + 4 checksum)
        # Use a well-known test address pattern
        import base64
        public_key = b"\x01" * 32
        checksum = b"\x00" * 4
        address = base64.b32encode(public_key + checksum).decode().rstrip("=")

        result = _decode_algorand_address(address)
        assert len(result) == 32
        assert result == public_key

    def test_extracts_public_key_portion(self):
        import base64
        key = bytes(range(32))
        checksum = b"\xab\xcd\xef\x01"
        address = base64.b32encode(key + checksum).decode().rstrip("=")

        result = _decode_algorand_address(address)
        assert result == key


# ============================================================================
# _parse_key_announcement
# ============================================================================


class TestParseKeyAnnouncement:
    def test_returns_none_for_short_note(self):
        result = _parse_key_announcement(b"\x00" * 16, "SOMEADDR")
        assert result is None

    def test_returns_none_for_empty_note(self):
        result = _parse_key_announcement(b"", "SOMEADDR")
        assert result is None

    def test_parses_32_byte_key_unverified(self):
        """32-byte note = public key only, no signature → unverified."""
        key = b"\xab" * 32
        result = _parse_key_announcement(key, "SOMEADDR")
        assert result is not None
        assert result.public_key == key
        assert result.is_verified is False

    def test_parses_key_between_32_and_96_bytes_unverified(self):
        """Note between 32 and 96 bytes: has key but signature is incomplete."""
        note = b"\xab" * 64  # 32 key + 32 partial sig
        result = _parse_key_announcement(note, "SOMEADDR")
        assert result is not None
        assert result.public_key == b"\xab" * 32
        assert result.is_verified is False

    def test_parses_key_with_valid_signature(self):
        """96-byte note with valid signature should be verified."""
        seed = b"\x01" * 32
        ed25519_private = Ed25519PrivateKey.from_private_bytes(seed)
        ed25519_public = ed25519_private.public_key().public_bytes_raw()

        # Derive the encryption public key
        _, encryption_public_key = derive_keys_from_seed(seed)
        enc_pub_bytes = public_key_to_bytes(encryption_public_key)

        # Sign the encryption key with the Ed25519 key
        signature = sign_encryption_key(enc_pub_bytes, ed25519_private)

        # Build the announcement note: 32-byte key + 64-byte signature
        note = enc_pub_bytes + signature

        # Build a valid address from the ed25519 public key
        import base64
        checksum = b"\x00" * 4
        address = base64.b32encode(ed25519_public + checksum).decode().rstrip("=")

        result = _parse_key_announcement(note, address)
        assert result is not None
        assert result.public_key == enc_pub_bytes
        assert result.is_verified is True

    def test_parses_key_with_invalid_signature(self):
        """96-byte note with bad signature should be unverified."""
        key = b"\xab" * 32
        bad_signature = b"\x00" * 64
        note = key + bad_signature

        # Use a valid-looking address
        import base64
        checksum = b"\x00" * 4
        address = base64.b32encode(b"\x01" * 32 + checksum).decode().rstrip("=")

        result = _parse_key_announcement(note, address)
        assert result is not None
        assert result.public_key == key
        assert result.is_verified is False


# ============================================================================
# discover_encryption_key
# ============================================================================


class TestDiscoverEncryptionKey:
    @pytest.mark.asyncio
    async def test_returns_none_when_no_transactions(self):
        indexer = MockIndexerClient()
        result = await discover_encryption_key(indexer, "SOMEADDR")
        assert result is None

    @pytest.mark.asyncio
    async def test_finds_key_in_self_transfer(self):
        indexer = MockIndexerClient()
        address = "ALICE"
        key = b"\xcd" * 32

        indexer.add_transaction(NoteTransaction(
            txid="announce-1",
            sender=address,
            receiver=address,  # Self-transfer
            note=key,
            confirmed_round=50,
            round_time=1700000000,
        ))

        result = await discover_encryption_key(indexer, address)
        assert result is not None
        assert result.public_key == key

    @pytest.mark.asyncio
    async def test_ignores_non_self_transfers(self):
        indexer = MockIndexerClient()
        address = "ALICE"

        indexer.add_transaction(NoteTransaction(
            txid="transfer-1",
            sender=address,
            receiver="BOB",  # Not self-transfer
            note=b"\xab" * 32,
            confirmed_round=50,
            round_time=1700000000,
        ))

        result = await discover_encryption_key(indexer, address)
        assert result is None

    @pytest.mark.asyncio
    async def test_ignores_short_notes(self):
        indexer = MockIndexerClient()
        address = "ALICE"

        indexer.add_transaction(NoteTransaction(
            txid="short-note",
            sender=address,
            receiver=address,
            note=b"\x00" * 16,  # Too short to be a key
            confirmed_round=50,
            round_time=1700000000,
        ))

        result = await discover_encryption_key(indexer, address)
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_first_valid_announcement(self):
        """When multiple announcements exist, return the first valid one."""
        indexer = MockIndexerClient()
        address = "ALICE"

        indexer.add_transaction(NoteTransaction(
            txid="announce-1",
            sender=address,
            receiver=address,
            note=b"\x01" * 32,
            confirmed_round=50,
            round_time=1700000000,
        ))
        indexer.add_transaction(NoteTransaction(
            txid="announce-2",
            sender=address,
            receiver=address,
            note=b"\x02" * 32,
            confirmed_round=60,
            round_time=1700000001,
        ))

        result = await discover_encryption_key(indexer, address)
        assert result is not None
        assert result.public_key == b"\x01" * 32  # First one wins

    @pytest.mark.asyncio
    async def test_skips_transactions_from_others(self):
        """Only self-sent transactions count as key announcements."""
        indexer = MockIndexerClient()
        address = "ALICE"

        # Someone else sends to Alice with a 32-byte note
        indexer.add_transaction(NoteTransaction(
            txid="from-bob",
            sender="BOB",
            receiver=address,
            note=b"\xab" * 32,
            confirmed_round=50,
            round_time=1700000000,
        ))

        result = await discover_encryption_key(indexer, address)
        assert result is None


# ============================================================================
# Data Models
# ============================================================================


class TestNoteTransaction:
    def test_fields(self):
        tx = NoteTransaction(
            txid="abc123",
            sender="ALICE",
            receiver="BOB",
            note=b"hello",
            confirmed_round=42,
            round_time=1700000000,
        )
        assert tx.txid == "abc123"
        assert tx.sender == "ALICE"
        assert tx.receiver == "BOB"
        assert tx.note == b"hello"
        assert tx.confirmed_round == 42
        assert tx.round_time == 1700000000


class TestTransactionInfo:
    def test_with_confirmed_round(self):
        info = TransactionInfo(txid="abc", confirmed_round=100)
        assert info.txid == "abc"
        assert info.confirmed_round == 100

    def test_without_confirmed_round(self):
        info = TransactionInfo(txid="abc")
        assert info.confirmed_round is None


class TestSuggestedParams:
    def test_fields(self):
        params = SuggestedParams(
            fee=1000, min_fee=1000, first_valid=100,
            last_valid=200, genesis_id="test", genesis_hash=b"\x00" * 32,
        )
        assert params.fee == 1000
        assert params.first_valid == 100


class TestAccountInfo:
    def test_fields(self):
        info = AccountInfo(address="ALICE", amount=1_000_000, min_balance=100_000)
        assert info.address == "ALICE"
        assert info.amount == 1_000_000
