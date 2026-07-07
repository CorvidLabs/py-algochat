"""Tests for storage interfaces and implementations."""

import pytest
import stat
from datetime import datetime, timedelta
from algochat.storage import (
    InMemoryMessageCache,
    PublicKeyCache,
    InMemoryKeyStorage,
    FileKeyStorage,
)
from algochat.models import Message, MessageDirection


# ============================================================================
# Fixtures
# ============================================================================


def make_message(
    id: str = "txid-1",
    confirmed_round: int = 100,
    timestamp: datetime | None = None,
) -> Message:
    return Message(
        id=id,
        sender="ALICE",
        recipient="BOB",
        content=f"msg-{id}",
        timestamp=timestamp or datetime(2026, 3, 5, 12, 0, 0),
        confirmed_round=confirmed_round,
        direction=MessageDirection.SENT,
    )


# ============================================================================
# InMemoryMessageCache
# ============================================================================


class TestInMemoryMessageCache:
    @pytest.fixture
    def cache(self):
        return InMemoryMessageCache()

    @pytest.mark.asyncio
    async def test_store_and_retrieve(self, cache):
        msg = make_message()
        await cache.store([msg], "BOB")
        result = await cache.retrieve("BOB")
        assert len(result) == 1
        assert result[0].id == "txid-1"

    @pytest.mark.asyncio
    async def test_retrieve_empty(self, cache):
        result = await cache.retrieve("NOBODY")
        assert result == []

    @pytest.mark.asyncio
    async def test_store_deduplicates(self, cache):
        msg = make_message()
        await cache.store([msg, msg], "BOB")
        result = await cache.retrieve("BOB")
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_store_multiple_calls_dedup(self, cache):
        msg = make_message()
        await cache.store([msg], "BOB")
        await cache.store([msg], "BOB")
        result = await cache.retrieve("BOB")
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_store_sorts_by_timestamp(self, cache):
        m1 = make_message(id="txid-1", timestamp=datetime(2026, 3, 5, 14, 0, 0))
        m2 = make_message(id="txid-2", timestamp=datetime(2026, 3, 5, 12, 0, 0))
        await cache.store([m1, m2], "BOB")
        result = await cache.retrieve("BOB")
        assert result[0].id == "txid-2"
        assert result[1].id == "txid-1"

    @pytest.mark.asyncio
    async def test_retrieve_after_round(self, cache):
        m1 = make_message(id="txid-1", confirmed_round=100)
        m2 = make_message(id="txid-2", confirmed_round=200)
        await cache.store([m1, m2], "BOB")
        result = await cache.retrieve("BOB", after_round=150)
        assert len(result) == 1
        assert result[0].id == "txid-2"

    @pytest.mark.asyncio
    async def test_sync_round(self, cache):
        assert await cache.get_last_sync_round("BOB") is None
        await cache.set_last_sync_round(500, "BOB")
        assert await cache.get_last_sync_round("BOB") == 500

    @pytest.mark.asyncio
    async def test_get_cached_conversations(self, cache):
        await cache.store([make_message(id="txid-1")], "BOB")
        await cache.store([make_message(id="txid-2")], "CAROL")
        convs = await cache.get_cached_conversations()
        assert set(convs) == {"BOB", "CAROL"}

    @pytest.mark.asyncio
    async def test_clear(self, cache):
        await cache.store([make_message()], "BOB")
        await cache.set_last_sync_round(100, "BOB")
        await cache.clear()
        assert await cache.retrieve("BOB") == []
        assert await cache.get_last_sync_round("BOB") is None
        assert await cache.get_cached_conversations() == []

    @pytest.mark.asyncio
    async def test_clear_for(self, cache):
        await cache.store([make_message(id="txid-1")], "BOB")
        await cache.store([make_message(id="txid-2")], "CAROL")
        await cache.set_last_sync_round(100, "BOB")
        await cache.clear_for("BOB")
        assert await cache.retrieve("BOB") == []
        assert await cache.get_last_sync_round("BOB") is None
        result = await cache.retrieve("CAROL")
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_retrieve_returns_copy(self, cache):
        """Mutating the returned list shouldn't affect the cache."""
        msg = make_message()
        await cache.store([msg], "BOB")
        result = await cache.retrieve("BOB")
        result.clear()
        assert len(await cache.retrieve("BOB")) == 1


# ============================================================================
# PublicKeyCache
# ============================================================================


class TestPublicKeyCache:
    @pytest.fixture
    def key_cache(self):
        return PublicKeyCache(ttl=timedelta(hours=1))

    @pytest.mark.asyncio
    async def test_store_and_retrieve(self, key_cache):
        await key_cache.store("ALICE", b"\x01" * 32)
        result = await key_cache.retrieve("ALICE")
        assert result == b"\x01" * 32

    @pytest.mark.asyncio
    async def test_retrieve_missing(self, key_cache):
        result = await key_cache.retrieve("NOBODY")
        assert result is None

    @pytest.mark.asyncio
    async def test_expired_returns_none(self):
        cache = PublicKeyCache(ttl=timedelta(seconds=0))
        await cache.store("ALICE", b"\x01" * 32)
        # TTL of 0 means it expires immediately
        result = await cache.retrieve("ALICE")
        assert result is None

    @pytest.mark.asyncio
    async def test_invalidate(self, key_cache):
        await key_cache.store("ALICE", b"\x01" * 32)
        await key_cache.invalidate("ALICE")
        assert await key_cache.retrieve("ALICE") is None

    @pytest.mark.asyncio
    async def test_invalidate_nonexistent(self, key_cache):
        # Should not raise
        await key_cache.invalidate("NOBODY")

    @pytest.mark.asyncio
    async def test_clear(self, key_cache):
        await key_cache.store("ALICE", b"\x01" * 32)
        await key_cache.store("BOB", b"\x02" * 32)
        await key_cache.clear()
        assert await key_cache.retrieve("ALICE") is None
        assert await key_cache.retrieve("BOB") is None

    @pytest.mark.asyncio
    async def test_prune_expired(self):
        cache = PublicKeyCache(ttl=timedelta(seconds=0))
        await cache.store("ALICE", b"\x01" * 32)
        await cache.prune_expired()
        # After pruning, internal cache should be empty
        assert await cache.retrieve("ALICE") is None

    @pytest.mark.asyncio
    async def test_overwrite_key(self, key_cache):
        await key_cache.store("ALICE", b"\x01" * 32)
        await key_cache.store("ALICE", b"\x02" * 32)
        result = await key_cache.retrieve("ALICE")
        assert result == b"\x02" * 32


# ============================================================================
# InMemoryKeyStorage
# ============================================================================


class TestInMemoryKeyStorage:
    @pytest.fixture
    def storage(self):
        return InMemoryKeyStorage()

    @pytest.mark.asyncio
    async def test_store_and_retrieve(self, storage):
        await storage.store(b"\x01" * 32, "ALICE")
        result = await storage.retrieve("ALICE")
        assert result == b"\x01" * 32

    @pytest.mark.asyncio
    async def test_retrieve_missing_raises(self, storage):
        with pytest.raises(KeyError):
            await storage.retrieve("NOBODY")

    @pytest.mark.asyncio
    async def test_has_key(self, storage):
        assert await storage.has_key("ALICE") is False
        await storage.store(b"\x01" * 32, "ALICE")
        assert await storage.has_key("ALICE") is True

    @pytest.mark.asyncio
    async def test_delete(self, storage):
        await storage.store(b"\x01" * 32, "ALICE")
        await storage.delete("ALICE")
        assert await storage.has_key("ALICE") is False

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, storage):
        # Should not raise
        await storage.delete("NOBODY")

    @pytest.mark.asyncio
    async def test_list_stored_addresses(self, storage):
        await storage.store(b"\x01" * 32, "ALICE")
        await storage.store(b"\x02" * 32, "BOB")
        addrs = await storage.list_stored_addresses()
        assert set(addrs) == {"ALICE", "BOB"}

    @pytest.mark.asyncio
    async def test_list_empty(self, storage):
        assert await storage.list_stored_addresses() == []

    @pytest.mark.asyncio
    async def test_overwrite_key(self, storage):
        await storage.store(b"\x01" * 32, "ALICE")
        await storage.store(b"\x02" * 32, "ALICE")
        result = await storage.retrieve("ALICE")
        assert result == b"\x02" * 32

    @pytest.mark.asyncio
    async def test_biometric_param_accepted(self, storage):
        """require_biometric is accepted but ignored in memory impl."""
        await storage.store(b"\x01" * 32, "ALICE", require_biometric=True)
        result = await storage.retrieve("ALICE")
        assert result == b"\x01" * 32


# ============================================================================
# FileKeyStorage
# ============================================================================


class TestFileKeyStorage:
    @pytest.fixture
    def storage(self, tmp_path):
        return FileKeyStorage(password="correct horse battery staple", base_dir=tmp_path)

    @pytest.mark.asyncio
    async def test_store_and_retrieve_roundtrip(self, storage):
        key = b"\x07" * 32
        await storage.store(key, "ALICE")
        result = await storage.retrieve("ALICE")
        assert result == key

    @pytest.mark.asyncio
    async def test_file_format_is_92_bytes(self, storage, tmp_path):
        await storage.store(b"\x07" * 32, "ALICE")
        data = (tmp_path / "ALICE.key").read_bytes()
        # salt(32) + nonce(12) + ciphertext(32) + tag(16) = 92 bytes
        assert len(data) == 92

    @pytest.mark.asyncio
    async def test_file_has_0600_permissions(self, storage, tmp_path):
        await storage.store(b"\x07" * 32, "ALICE")
        mode = stat.S_IMODE((tmp_path / "ALICE.key").stat().st_mode)
        assert mode == 0o600

    @pytest.mark.asyncio
    async def test_key_is_encrypted_on_disk(self, storage, tmp_path):
        key = b"\x07" * 32
        await storage.store(key, "ALICE")
        data = (tmp_path / "ALICE.key").read_bytes()
        # The plaintext key must not appear verbatim in the encrypted file.
        assert key not in data

    @pytest.mark.asyncio
    async def test_wrong_password_fails(self, tmp_path):
        good = FileKeyStorage(password="right-password", base_dir=tmp_path)
        await good.store(b"\x07" * 32, "ALICE")

        bad = FileKeyStorage(password="wrong-password", base_dir=tmp_path)
        with pytest.raises(Exception):
            await bad.retrieve("ALICE")

    @pytest.mark.asyncio
    async def test_retrieve_missing_raises(self, storage):
        with pytest.raises(KeyError):
            await storage.retrieve("NOBODY")

    @pytest.mark.asyncio
    async def test_has_key(self, storage):
        assert await storage.has_key("ALICE") is False
        await storage.store(b"\x07" * 32, "ALICE")
        assert await storage.has_key("ALICE") is True

    @pytest.mark.asyncio
    async def test_delete(self, storage):
        await storage.store(b"\x07" * 32, "ALICE")
        await storage.delete("ALICE")
        assert await storage.has_key("ALICE") is False

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, storage):
        await storage.delete("NOBODY")  # Should not raise

    @pytest.mark.asyncio
    async def test_list_stored_addresses(self, storage):
        await storage.store(b"\x01" * 32, "ALICE")
        await storage.store(b"\x02" * 32, "BOB")
        addrs = await storage.list_stored_addresses()
        assert set(addrs) == {"ALICE", "BOB"}

    @pytest.mark.asyncio
    async def test_list_empty(self, storage):
        assert await storage.list_stored_addresses() == []

    @pytest.mark.asyncio
    async def test_overwrite_key(self, storage):
        await storage.store(b"\x01" * 32, "ALICE")
        await storage.store(b"\x02" * 32, "ALICE")
        result = await storage.retrieve("ALICE")
        assert result == b"\x02" * 32

    @pytest.mark.asyncio
    async def test_rejects_wrong_key_length(self, storage):
        with pytest.raises(ValueError):
            await storage.store(b"\x01" * 16, "ALICE")

    @pytest.mark.asyncio
    async def test_different_salts_per_store(self, storage, tmp_path):
        """Each store call must use a fresh random salt and nonce."""
        await storage.store(b"\x07" * 32, "ALICE")
        first = (tmp_path / "ALICE.key").read_bytes()
        await storage.store(b"\x07" * 32, "ALICE")
        second = (tmp_path / "ALICE.key").read_bytes()
        # Same key + password but different salt/nonce → different ciphertext.
        assert first != second
        # But both decrypt to the same value.
        assert await storage.retrieve("ALICE") == b"\x07" * 32
