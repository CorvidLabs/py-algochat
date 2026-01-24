"""
File-based encryption key storage with password protection.

Stores X25519 encryption keys encrypted with AES-256-GCM, using a password
derived key via PBKDF2. Keys are stored in `~/.algochat/keys/`.

## Storage Format

Each key file contains:
- Salt: 32 bytes (random, for PBKDF2)
- Nonce: 12 bytes (random, for AES-GCM)
- Ciphertext: 32 bytes (encrypted private key)
- Tag: 16 bytes (authentication tag)

## Security

- Uses PBKDF2 with 100,000 iterations for key derivation
- Uses AES-256-GCM for authenticated encryption
- Keys are stored with 600 permissions (owner read/write only)
- Salt is unique per key file
"""

import os
from pathlib import Path
from typing import Optional, List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from .encryption_key_storage import EncryptionKeyStorage, KeyNotFoundError


class PasswordRequiredError(Exception):
    """Raised when password is required but not set."""

    def __init__(self) -> None:
        super().__init__("Password is required for file key storage")


class DecryptionFailedError(Exception):
    """Raised when decryption fails (wrong password)."""

    def __init__(self) -> None:
        super().__init__("Decryption failed - incorrect password or corrupted data")


class InvalidKeyDataError(Exception):
    """Raised when key data is invalid."""

    def __init__(self) -> None:
        super().__init__("Invalid key data format")


class FileKeyStorage(EncryptionKeyStorage):
    """
    File-based encryption key storage with password protection.

    Example usage:
        ```python
        storage = FileKeyStorage(password="user-password")

        # Store a key
        await storage.store(private_key, "ADDRESS...")

        # Retrieve
        key = await storage.retrieve("ADDRESS...")
        ```
    """

    # PBKDF2 iteration count (OWASP recommendation for SHA256)
    PBKDF2_ITERATIONS = 100_000

    # Salt size in bytes
    SALT_SIZE = 32

    # AES-GCM nonce size in bytes
    NONCE_SIZE = 12

    # AES-GCM tag size in bytes
    TAG_SIZE = 16

    # Directory name for key storage
    DIRECTORY_NAME = ".algochat/keys"

    # Minimum file size (salt + nonce + ciphertext + tag)
    MIN_FILE_SIZE = 32 + 12 + 32 + 16  # 92 bytes

    def __init__(self, password: Optional[str] = None) -> None:
        """
        Create a new file key storage.

        Args:
            password: Optional password for encryption. If not provided,
                      must be set before use.
        """
        self._password = password
        self._cached_derived_key: Optional[bytes] = None
        self._cached_salt: Optional[bytes] = None

    def set_password(self, password: str) -> None:
        """
        Set the password for encryption/decryption.

        Args:
            password: The password to use.
        """
        self._password = password
        self._cached_derived_key = None
        self._cached_salt = None

    def clear_password(self) -> None:
        """Clear the password and cached keys from memory."""
        self._password = None
        self._cached_derived_key = None
        self._cached_salt = None

    async def store(
        self,
        private_key: bytes,
        address: str,
        require_biometric: bool = False,
    ) -> None:
        """
        Store a private key for an address.

        Args:
            private_key: The 32-byte X25519 private key.
            address: The Algorand address.
            require_biometric: Ignored for file storage.

        Raises:
            PasswordRequiredError: If no password is set.
        """
        if not self._password:
            raise PasswordRequiredError()

        # Ensure directory exists
        directory = self._ensure_directory()

        # Generate random salt and nonce
        salt = os.urandom(self.SALT_SIZE)
        nonce = os.urandom(self.NONCE_SIZE)

        # Derive encryption key from password
        derived_key = self._derive_key(self._password, salt)

        # Encrypt the private key with AES-256-GCM
        aesgcm = AESGCM(derived_key)
        ciphertext_and_tag = aesgcm.encrypt(nonce, private_key, None)

        # Combine: salt + nonce + ciphertext + tag
        file_data = salt + nonce + ciphertext_and_tag

        # Write to file
        file_path = self._key_file_path(address, directory)
        file_path.write_bytes(file_data)

        # Set restrictive permissions (owner read/write only)
        self._set_restrictive_permissions(file_path)

    async def retrieve(self, address: str) -> bytes:
        """
        Retrieve a private key for an address.

        Args:
            address: The Algorand address.

        Returns:
            The 32-byte X25519 private key.

        Raises:
            PasswordRequiredError: If no password is set.
            KeyNotFoundError: If no key is stored for this address.
            DecryptionFailedError: If decryption fails (wrong password).
            InvalidKeyDataError: If the key data is corrupted.
        """
        if not self._password:
            raise PasswordRequiredError()

        directory = self._get_directory()
        file_path = self._key_file_path(address, directory)

        # Check if file exists
        if not file_path.exists():
            raise KeyNotFoundError(address)

        # Read the encrypted file
        file_data = file_path.read_bytes()

        # Validate minimum size
        if len(file_data) < self.MIN_FILE_SIZE:
            raise InvalidKeyDataError()

        # Parse: salt + nonce + ciphertext + tag
        salt = file_data[: self.SALT_SIZE]
        nonce = file_data[self.SALT_SIZE : self.SALT_SIZE + self.NONCE_SIZE]
        ciphertext_and_tag = file_data[self.SALT_SIZE + self.NONCE_SIZE :]

        # Derive decryption key from password
        derived_key = self._derive_key(self._password, salt)

        # Decrypt
        try:
            aesgcm = AESGCM(derived_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, None)
            return plaintext
        except Exception as e:
            raise DecryptionFailedError() from e

    async def has_key(self, address: str) -> bool:
        """
        Check if a key exists for an address.

        Args:
            address: The Algorand address.

        Returns:
            True if a key is stored for this address.
        """
        directory = self._get_directory()
        file_path = self._key_file_path(address, directory)
        return file_path.exists()

    async def delete(self, address: str) -> None:
        """
        Delete a key for an address.

        Args:
            address: The Algorand address.
        """
        directory = self._get_directory()
        file_path = self._key_file_path(address, directory)

        if file_path.exists():
            file_path.unlink()

    async def list_stored_addresses(self) -> List[str]:
        """
        List all stored addresses.

        Returns:
            List of addresses with stored keys.
        """
        directory = self._get_directory()

        if not directory.exists():
            return []

        return [
            f.stem
            for f in directory.iterdir()
            if f.suffix == ".key"
        ]

    def _get_directory(self) -> Path:
        """Get the key storage directory path."""
        return Path.home() / self.DIRECTORY_NAME

    def _ensure_directory(self) -> Path:
        """Ensure the key storage directory exists."""
        directory = self._get_directory()
        directory.mkdir(parents=True, exist_ok=True)
        # Set directory permissions to 700 (owner only)
        try:
            directory.chmod(0o700)
        except OSError:
            pass  # Ignore permission errors on some platforms
        return directory

    def _key_file_path(self, address: str, directory: Path) -> Path:
        """Return the file path for a key."""
        return directory / f"{address}.key"

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive an encryption key from password using PBKDF2."""
        # Check cache
        if self._cached_derived_key and self._cached_salt == salt:
            return self._cached_derived_key

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )
        derived_key = kdf.derive(password.encode("utf-8"))

        # Cache for this salt
        self._cached_derived_key = derived_key
        self._cached_salt = salt

        return derived_key

    def _set_restrictive_permissions(self, file_path: Path) -> None:
        """Set restrictive file permissions (600 on Unix)."""
        try:
            file_path.chmod(0o600)
        except OSError:
            pass  # Ignore permission errors on some platforms
