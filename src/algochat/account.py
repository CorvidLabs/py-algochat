"""
Chat account for AlgoChat.

A ChatAccount wraps an Algorand address with derived X25519 encryption keys
for secure messaging.
"""

from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .keys import derive_keys_from_seed, public_key_to_bytes
from .storage import EncryptionKeyStorage


@dataclass
class ChatAccount:
    """
    A chat-enabled Algorand account with encryption keys.

    The ChatAccount wraps an Algorand address with derived X25519 encryption keys.
    The private key should be stored securely using an EncryptionKeyStorage implementation.

    Attributes:
        address: The Algorand address (58 characters).
        encryption_private_key: The X25519 private key for decryption.
        encryption_public_key: The X25519 public key for encryption.
        ed25519_public_key: The Ed25519 public key from the Algorand account (optional).
    """

    address: str
    encryption_private_key: X25519PrivateKey
    encryption_public_key: X25519PublicKey
    ed25519_public_key: Optional[bytes] = None

    @classmethod
    def from_seed(cls, address: str, seed: bytes) -> "ChatAccount":
        """
        Create a ChatAccount from a 32-byte seed.

        This derives the X25519 encryption keys from the seed using HKDF-SHA256.

        Args:
            address: The Algorand address.
            seed: 32-byte seed (typically first 32 bytes of Algorand secret key).

        Returns:
            A new ChatAccount instance.

        Raises:
            ValueError: If seed is not 32 bytes.
        """
        private_key, public_key = derive_keys_from_seed(seed)
        return cls(
            address=address,
            encryption_private_key=private_key,
            encryption_public_key=public_key,
        )

    @classmethod
    def from_algorand_account(cls, address: str, secret_key: bytes) -> "ChatAccount":
        """
        Create a ChatAccount from an Algorand secret key.

        The Algorand secret key is 64 bytes: the first 32 are the seed,
        and the last 32 are the Ed25519 public key.

        Args:
            address: The Algorand address.
            secret_key: 64-byte Algorand secret key.

        Returns:
            A new ChatAccount instance.

        Raises:
            ValueError: If secret_key is not 64 bytes.
        """
        if len(secret_key) != 64:
            raise ValueError(f"Secret key must be 64 bytes, got {len(secret_key)}")

        seed = secret_key[:32]
        ed25519_public_key = secret_key[32:]

        private_key, public_key = derive_keys_from_seed(seed)
        return cls(
            address=address,
            encryption_private_key=private_key,
            encryption_public_key=public_key,
            ed25519_public_key=ed25519_public_key,
        )

    @classmethod
    async def from_storage(
        cls,
        address: str,
        storage: EncryptionKeyStorage,
        ed25519_public_key: Optional[bytes] = None,
    ) -> "ChatAccount":
        """
        Create a ChatAccount by retrieving the encryption key from storage.

        This allows loading an account without the full mnemonic, useful when
        the encryption key was previously saved with biometric protection.

        Args:
            address: The Algorand address.
            storage: The key storage to retrieve from.
            ed25519_public_key: Optional Ed25519 public key for the account.

        Returns:
            A new ChatAccount instance.

        Raises:
            KeyNotFoundError: If no key is stored for this address.
        """
        private_key_bytes = await storage.retrieve(address)
        private_key = X25519PrivateKey.from_private_bytes(private_key_bytes)
        public_key = private_key.public_key()

        return cls(
            address=address,
            encryption_private_key=private_key,
            encryption_public_key=public_key,
            ed25519_public_key=ed25519_public_key,
        )

    @property
    def public_key_bytes(self) -> bytes:
        """The encryption public key as raw bytes (32 bytes)."""
        return public_key_to_bytes(self.encryption_public_key)

    def private_key_bytes(self) -> bytes:
        """
        The encryption private key as raw bytes (32 bytes).

        Warning: Handle with care. This should only be used for secure storage.
        """
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
        return self.encryption_private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )

    async def save_encryption_key(
        self,
        storage: EncryptionKeyStorage,
        require_biometric: bool = True,
    ) -> None:
        """
        Save the encryption key to storage.

        This allows the account to be loaded later without the full mnemonic.

        Args:
            storage: The key storage to save to.
            require_biometric: If True, require biometric authentication to retrieve.
        """
        await storage.store(
            private_key=self.private_key_bytes(),
            address=self.address,
            require_biometric=require_biometric,
        )

    async def has_stored_encryption_key(self, storage: EncryptionKeyStorage) -> bool:
        """
        Check if an encryption key is stored for this account.

        Args:
            storage: The key storage to check.

        Returns:
            True if a key exists in storage for this address.
        """
        return await storage.has_key(self.address)

    async def delete_stored_encryption_key(self, storage: EncryptionKeyStorage) -> None:
        """
        Delete the stored encryption key for this account.

        Args:
            storage: The key storage to delete from.
        """
        await storage.delete(self.address)

    def __repr__(self) -> str:
        return f"ChatAccount({self.address})"

    def __str__(self) -> str:
        return f"ChatAccount({self.address})"
