"""Public key cache with TTL expiration."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional


@dataclass
class _CacheEntry:
    """Entry in the public key cache with expiration."""
    key: bytes
    expires_at: datetime


# Default TTL: 24 hours
DEFAULT_TTL = timedelta(hours=24)


class PublicKeyCache:
    """In-memory cache for public keys with TTL expiration."""

    def __init__(self, ttl: timedelta = DEFAULT_TTL) -> None:
        """Creates a new public key cache with the given TTL (default: 24 hours)."""
        self._cache: dict[str, _CacheEntry] = {}
        self._ttl = ttl

    def store(self, address: str, key: bytes) -> None:
        """Store a public key for an address."""
        self._cache[address] = _CacheEntry(
            key=bytes(key),
            expires_at=datetime.now() + self._ttl,
        )

    def retrieve(self, address: str) -> Optional[bytes]:
        """Retrieve a public key for an address (returns None if expired)."""
        entry = self._cache.get(address)
        if entry is None:
            return None

        if entry.expires_at <= datetime.now():
            del self._cache[address]
            return None

        return bytes(entry.key)

    def invalidate(self, address: str) -> None:
        """Invalidate the cached key for an address."""
        self._cache.pop(address, None)

    def clear(self) -> None:
        """Clear all cached keys."""
        self._cache.clear()

    def prune_expired(self) -> None:
        """Remove all expired entries."""
        now = datetime.now()
        expired = [addr for addr, entry in self._cache.items() if entry.expires_at <= now]
        for addr in expired:
            del self._cache[addr]
