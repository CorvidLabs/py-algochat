"""
Storage interfaces and implementations for AlgoChat.

This module provides abstract base classes and implementations for storing messages,
caching public keys, and persisting encryption keys.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional
import asyncio

from .models import Message


# ============================================================================
# Message Cache
# ============================================================================


class MessageCache(ABC):
    """Abstract base class for storing and retrieving messages."""

    @abstractmethod
    async def store(self, messages: list[Message], participant: str) -> None:
        """Store messages for a conversation."""
        pass

    @abstractmethod
    async def retrieve(
        self, participant: str, after_round: Optional[int] = None
    ) -> list[Message]:
        """Retrieve cached messages for a conversation."""
        pass

    @abstractmethod
    async def get_last_sync_round(self, participant: str) -> Optional[int]:
        """Get the last synced round for a conversation."""
        pass

    @abstractmethod
    async def set_last_sync_round(self, round: int, participant: str) -> None:
        """Set the last synced round for a conversation."""
        pass

    @abstractmethod
    async def get_cached_conversations(self) -> list[str]:
        """Get all cached conversation participants."""
        pass

    @abstractmethod
    async def clear(self) -> None:
        """Clear all cached data."""
        pass

    @abstractmethod
    async def clear_for(self, participant: str) -> None:
        """Clear cached data for a specific conversation."""
        pass


class InMemoryMessageCache(MessageCache):
    """In-memory implementation of MessageCache."""

    def __init__(self) -> None:
        self._messages: dict[str, list[Message]] = {}
        self._sync_rounds: dict[str, int] = {}
        self._lock = asyncio.Lock()

    async def store(self, messages: list[Message], participant: str) -> None:
        async with self._lock:
            if participant not in self._messages:
                self._messages[participant] = []

            existing_ids = {m.id for m in self._messages[participant]}
            for message in messages:
                if message.id not in existing_ids:
                    self._messages[participant].append(message)
                    existing_ids.add(message.id)

            self._messages[participant].sort(key=lambda m: m.timestamp)

    async def retrieve(
        self, participant: str, after_round: Optional[int] = None
    ) -> list[Message]:
        async with self._lock:
            messages = self._messages.get(participant, []).copy()

            if after_round is not None:
                messages = [m for m in messages if m.confirmed_round > after_round]

            return messages

    async def get_last_sync_round(self, participant: str) -> Optional[int]:
        async with self._lock:
            return self._sync_rounds.get(participant)

    async def set_last_sync_round(self, round: int, participant: str) -> None:
        async with self._lock:
            self._sync_rounds[participant] = round

    async def get_cached_conversations(self) -> list[str]:
        async with self._lock:
            return list(self._messages.keys())

    async def clear(self) -> None:
        async with self._lock:
            self._messages.clear()
            self._sync_rounds.clear()

    async def clear_for(self, participant: str) -> None:
        async with self._lock:
            self._messages.pop(participant, None)
            self._sync_rounds.pop(participant, None)


# ============================================================================
# Public Key Cache
# ============================================================================


@dataclass
class _CacheEntry:
    """Entry in the public key cache with expiration."""

    key: bytes
    expires_at: datetime


class PublicKeyCache:
    """In-memory cache for public keys with TTL expiration."""

    def __init__(self, ttl: timedelta = timedelta(hours=24)) -> None:
        self._cache: dict[str, _CacheEntry] = {}
        self._ttl = ttl
        self._lock = asyncio.Lock()

    async def store(self, address: str, key: bytes) -> None:
        """Store a public key for an address."""
        async with self._lock:
            self._cache[address] = _CacheEntry(
                key=key, expires_at=datetime.now() + self._ttl
            )

    async def retrieve(self, address: str) -> Optional[bytes]:
        """Retrieve a public key for an address (returns None if expired)."""
        async with self._lock:
            entry = self._cache.get(address)
            if entry is None:
                return None
            if entry.expires_at <= datetime.now():
                return None
            return entry.key

    async def invalidate(self, address: str) -> None:
        """Invalidate the cached key for an address."""
        async with self._lock:
            self._cache.pop(address, None)

    async def clear(self) -> None:
        """Clear all cached keys."""
        async with self._lock:
            self._cache.clear()

    async def prune_expired(self) -> None:
        """Remove all expired entries."""
        async with self._lock:
            now = datetime.now()
            expired = [addr for addr, entry in self._cache.items() if entry.expires_at <= now]
            for addr in expired:
                del self._cache[addr]


# ============================================================================
# Encryption Key Storage
# ============================================================================


class EncryptionKeyStorage(ABC):
    """Abstract base class for storing encryption private keys."""

    @abstractmethod
    async def store(
        self, private_key: bytes, address: str, require_biometric: bool = False
    ) -> None:
        """Store a private key for an address."""
        pass

    @abstractmethod
    async def retrieve(self, address: str) -> bytes:
        """Retrieve a private key for an address."""
        pass

    @abstractmethod
    async def has_key(self, address: str) -> bool:
        """Check if a key exists for an address."""
        pass

    @abstractmethod
    async def delete(self, address: str) -> None:
        """Delete a key for an address."""
        pass

    @abstractmethod
    async def list_stored_addresses(self) -> list[str]:
        """List all stored addresses."""
        pass


class InMemoryKeyStorage(EncryptionKeyStorage):
    """
    In-memory implementation of EncryptionKeyStorage (for testing).

    WARNING: This is NOT secure for production use. Keys are stored in memory
    without encryption and are lost when the process exits.
    """

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}
        self._lock = asyncio.Lock()

    async def store(
        self, private_key: bytes, address: str, require_biometric: bool = False
    ) -> None:
        async with self._lock:
            self._keys[address] = private_key

    async def retrieve(self, address: str) -> bytes:
        async with self._lock:
            key = self._keys.get(address)
            if key is None:
                raise KeyError(f"Key not found for address: {address}")
            return key

    async def has_key(self, address: str) -> bool:
        async with self._lock:
            return address in self._keys

    async def delete(self, address: str) -> None:
        async with self._lock:
            self._keys.pop(address, None)

    async def list_stored_addresses(self) -> list[str]:
        async with self._lock:
            return list(self._keys.keys())
