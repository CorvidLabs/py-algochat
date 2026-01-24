"""Encryption key storage interface and implementations."""

from abc import ABC, abstractmethod


class KeyNotFoundError(Exception):
    """Error thrown when a key is not found."""

    def __init__(self, address: str) -> None:
        super().__init__(f"Key not found for address: {address}")
        self.address = address


class EncryptionKeyStorage(ABC):
    """Interface for storing encryption private keys."""

    @abstractmethod
    async def store(
        self,
        private_key: bytes,
        address: str,
        require_biometric: bool = False,
    ) -> None:
        """Store a private key for an address."""
        ...

    @abstractmethod
    async def retrieve(self, address: str) -> bytes:
        """Retrieve a private key for an address."""
        ...

    @abstractmethod
    async def has_key(self, address: str) -> bool:
        """Check if a key exists for an address."""
        ...

    @abstractmethod
    async def delete(self, address: str) -> None:
        """Delete a key for an address."""
        ...

    @abstractmethod
    async def list_stored_addresses(self) -> list[str]:
        """List all stored addresses."""
        ...


class InMemoryKeyStorage(EncryptionKeyStorage):
    """
    In-memory implementation of EncryptionKeyStorage (for testing).

    WARNING: This is NOT secure for production use. Keys are stored in memory
    without encryption and are lost when the process exits.
    """

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}

    async def store(
        self,
        private_key: bytes,
        address: str,
        require_biometric: bool = False,
    ) -> None:
        """Store a private key for an address."""
        self._keys[address] = bytes(private_key)

    async def retrieve(self, address: str) -> bytes:
        """Retrieve a private key for an address."""
        key = self._keys.get(address)
        if key is None:
            raise KeyNotFoundError(address)
        return bytes(key)

    async def has_key(self, address: str) -> bool:
        """Check if a key exists for an address."""
        return address in self._keys

    async def delete(self, address: str) -> None:
        """Delete a key for an address."""
        self._keys.pop(address, None)

    async def list_stored_addresses(self) -> list[str]:
        """List all stored addresses."""
        return list(self._keys.keys())
