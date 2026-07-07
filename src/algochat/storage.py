"""
Storage interfaces and implementations for AlgoChat.

This module provides abstract base classes and implementations for storing messages,
caching public keys, and persisting encryption keys.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
import asyncio
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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


# File format and KDF constants for FileKeyStorage. These match the on-disk
# layout used by the Rust implementation so key files interoperate across
# implementations.
_FILE_SALT_SIZE = 32
_FILE_NONCE_SIZE = 12
_FILE_CIPHERTEXT_SIZE = 32  # encrypted 32-byte X25519 private key
_FILE_TAG_SIZE = 16
_FILE_TOTAL_SIZE = (
    _FILE_SALT_SIZE + _FILE_NONCE_SIZE + _FILE_CIPHERTEXT_SIZE + _FILE_TAG_SIZE
)  # 92 bytes
_PBKDF2_ITERATIONS = 100_000
_PRIVATE_KEY_SIZE = 32


class FileKeyStorage(EncryptionKeyStorage):
    """At-rest encrypted key storage backed by the local filesystem.

    Each private key is encrypted with AES-256-GCM using a key derived from a
    password via PBKDF2-HMAC-SHA256 (100,000 iterations), then written to
    ``~/.algochat/keys/<address>.key`` with mode ``0600``.

    On-disk format (92 bytes total)::

        salt        (32 bytes)
        nonce       (12 bytes)
        ciphertext  (32 bytes)  # encrypted private key
        tag         (16 bytes)  # AES-GCM authentication tag

    This layout interoperates with the Rust implementation.

    .. warning::
        AES-GCM in the ``cryptography`` library appends the tag to the
        ciphertext, so the stored ``ciphertext+tag`` block is the 48-byte
        output of a single ``AESGCM.encrypt`` call.
    """

    def __init__(self, password: str, base_dir: Optional[Path] = None) -> None:
        """Creates a file-backed key storage.

        Args:
            password: Password used to derive the AES-256 encryption key.
            base_dir: Directory in which to store key files. Defaults to
                ``~/.algochat/keys``.
        """
        if base_dir is None:
            base_dir = Path.home() / ".algochat" / "keys"
        self._base_dir = Path(base_dir)
        self._password = password.encode("utf-8")
        self._lock = asyncio.Lock()

    def _key_path(self, address: str) -> Path:
        return self._base_dir / f"{address}.key"

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=salt,
            iterations=_PBKDF2_ITERATIONS,
        )
        return kdf.derive(self._password)

    def _encrypt(self, private_key: bytes) -> bytes:
        salt = os.urandom(_FILE_SALT_SIZE)
        nonce = os.urandom(_FILE_NONCE_SIZE)
        derived = self._derive_key(salt)
        # AESGCM.encrypt returns ciphertext || tag (48 bytes for a 32-byte input).
        ciphertext_with_tag = AESGCM(derived).encrypt(nonce, private_key, None)
        return salt + nonce + ciphertext_with_tag

    def _decrypt(self, data: bytes) -> bytes:
        if len(data) != _FILE_TOTAL_SIZE:
            raise ValueError(
                f"Key file must be {_FILE_TOTAL_SIZE} bytes, got {len(data)}"
            )
        salt = data[:_FILE_SALT_SIZE]
        offset = _FILE_SALT_SIZE
        nonce = data[offset : offset + _FILE_NONCE_SIZE]
        offset += _FILE_NONCE_SIZE
        ciphertext_with_tag = data[offset:]
        derived = self._derive_key(salt)
        return AESGCM(derived).decrypt(nonce, ciphertext_with_tag, None)

    async def store(
        self, private_key: bytes, address: str, require_biometric: bool = False
    ) -> None:
        if len(private_key) != _PRIVATE_KEY_SIZE:
            raise ValueError(
                f"Private key must be {_PRIVATE_KEY_SIZE} bytes, got {len(private_key)}"
            )

        def _write() -> None:
            self._base_dir.mkdir(parents=True, exist_ok=True)
            encrypted = self._encrypt(private_key)
            path = self._key_path(address)
            # Write with restrictive permissions, then enforce 0600 in case of umask.
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, encrypted)
            finally:
                os.close(fd)
            os.chmod(path, 0o600)

        async with self._lock:
            await asyncio.to_thread(_write)

    async def retrieve(self, address: str) -> bytes:
        path = self._key_path(address)

        def _read() -> bytes:
            if not path.exists():
                raise KeyError(f"Key not found for address: {address}")
            return path.read_bytes()

        async with self._lock:
            data = await asyncio.to_thread(_read)
            return self._decrypt(data)

    async def has_key(self, address: str) -> bool:
        async with self._lock:
            return await asyncio.to_thread(self._key_path(address).exists)

    async def delete(self, address: str) -> None:
        path = self._key_path(address)

        def _delete() -> None:
            try:
                path.unlink()
            except FileNotFoundError:
                pass

        async with self._lock:
            await asyncio.to_thread(_delete)

    async def list_stored_addresses(self) -> list[str]:
        def _list() -> list[str]:
            if not self._base_dir.exists():
                return []
            return [p.stem for p in self._base_dir.glob("*.key")]

        async with self._lock:
            return await asyncio.to_thread(_list)
