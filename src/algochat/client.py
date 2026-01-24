"""
Main AlgoChat client for encrypted messaging on Algorand.

This module provides the primary interface for sending and receiving
encrypted messages using the AlgoChat protocol.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import asyncio

from .blockchain import (
    AlgorandConfig,
    AlgodClient,
    IndexerClient,
    NoteTransaction,
    discover_encryption_key,
)
from .crypto import encrypt_message, decrypt_message
from .envelope import encode_envelope, decode_envelope, is_chat_message
from .keys import derive_keys_from_seed
from .models import (
    Conversation,
    DiscoveredKey,
    Message,
    MessageDirection,
)
from .queue import SendQueue
from .storage import (
    EncryptionKeyStorage,
    InMemoryKeyStorage,
    MessageCache,
    InMemoryMessageCache,
    PublicKeyCache,
)
from .types import (
    InvalidEnvelopeError,
    PublicKeyNotFoundError,
    DecryptionError,
)


@dataclass
class AlgoChatConfig:
    """Configuration for the AlgoChat client."""

    network: AlgorandConfig
    """Algorand network configuration."""

    auto_discover_keys: bool = True
    """Whether to automatically discover recipient keys."""

    cache_public_keys: bool = True
    """Whether to cache public keys."""

    cache_messages: bool = True
    """Whether to cache messages locally."""

    @classmethod
    def localnet(cls) -> "AlgoChatConfig":
        """Creates a configuration for LocalNet."""
        return cls(network=AlgorandConfig.localnet())

    @classmethod
    def testnet(cls) -> "AlgoChatConfig":
        """Creates a configuration for TestNet."""
        return cls(network=AlgorandConfig.testnet())

    @classmethod
    def mainnet(cls) -> "AlgoChatConfig":
        """Creates a configuration for MainNet."""
        return cls(network=AlgorandConfig.mainnet())


class AlgoChat:
    """
    The main AlgoChat client for encrypted messaging.

    This provides a high-level API for sending and receiving encrypted
    messages on the Algorand blockchain.
    """

    def __init__(
        self,
        address: str,
        ed25519_public_key: bytes,
        encryption_private_key: bytes,
        encryption_public_key: bytes,
        config: AlgoChatConfig,
        algod: AlgodClient,
        indexer: IndexerClient,
        key_storage: EncryptionKeyStorage,
        message_cache: MessageCache,
    ) -> None:
        self._address = address
        self._ed25519_public_key = ed25519_public_key
        self._encryption_private_key = encryption_private_key
        self._encryption_public_key = encryption_public_key
        self._config = config
        self._algod = algod
        self._indexer = indexer
        self._key_storage = key_storage
        self._message_cache = message_cache
        self._public_key_cache = PublicKeyCache()
        self._send_queue = SendQueue()
        self._conversations: list[Conversation] = []
        self._lock = asyncio.Lock()

    @classmethod
    async def from_seed(
        cls,
        seed: bytes,
        address: str,
        config: AlgoChatConfig,
        algod: AlgodClient,
        indexer: IndexerClient,
        key_storage: Optional[EncryptionKeyStorage] = None,
        message_cache: Optional[MessageCache] = None,
    ) -> "AlgoChat":
        """
        Creates a new AlgoChat client from an Algorand account seed.

        The seed should be the 32-byte Ed25519 private key from an Algorand account.
        """
        if len(seed) != 32:
            raise ValueError("Seed must be 32 bytes")

        # Derive encryption keys from the seed
        encryption_private_key, encryption_public_key = derive_keys_from_seed(seed)

        # Use default storage if not provided
        if key_storage is None:
            key_storage = InMemoryKeyStorage()
        if message_cache is None:
            message_cache = InMemoryMessageCache()

        # Store the encryption key
        await key_storage.store(encryption_private_key, address, False)

        return cls(
            address=address,
            ed25519_public_key=seed,  # The seed is also the Ed25519 public key in Algorand
            encryption_private_key=encryption_private_key,
            encryption_public_key=encryption_public_key,
            config=config,
            algod=algod,
            indexer=indexer,
            key_storage=key_storage,
            message_cache=message_cache,
        )

    @property
    def address(self) -> str:
        """Returns the user's Algorand address."""
        return self._address

    @property
    def encryption_public_key(self) -> bytes:
        """Returns the user's encryption public key."""
        return self._encryption_public_key

    async def conversation(self, participant: str) -> Conversation:
        """Gets or creates a conversation with the given participant."""
        async with self._lock:
            for conv in self._conversations:
                if conv.participant == participant:
                    return conv

            conv = Conversation(participant)
            self._conversations.append(conv)
            return conv

    async def conversations(self) -> list[Conversation]:
        """Lists all conversations."""
        async with self._lock:
            return list(self._conversations)

    async def discover_key(self, address: str) -> Optional[DiscoveredKey]:
        """Discovers the encryption public key for an address."""
        # Check cache first
        if self._config.cache_public_keys:
            cached = await self._public_key_cache.retrieve(address)
            if cached is not None:
                return DiscoveredKey(public_key=cached, is_verified=True)

        # Search indexer for key announcement
        key = await discover_encryption_key(self._indexer, address)

        # Cache if found
        if key is not None and self._config.cache_public_keys:
            await self._public_key_cache.store(address, key.public_key)

        return key

    def encrypt(self, message: str, recipient_public_key: bytes) -> bytes:
        """Encrypts a message for a recipient."""
        ciphertext = encrypt_message(
            message.encode("utf-8"),
            recipient_public_key,
            self._encryption_private_key,
        )

        envelope = encode_envelope(
            ciphertext,
            self._encryption_public_key,
            recipient_public_key,
        )

        return envelope

    def decrypt(self, envelope: bytes, sender_public_key: bytes) -> str:
        """Decrypts a message from a sender."""
        if not is_chat_message(envelope):
            raise InvalidEnvelopeError("Not an AlgoChat message")

        decoded = decode_envelope(envelope)

        plaintext = decrypt_message(
            decoded.ciphertext,
            sender_public_key,
            self._encryption_private_key,
        )

        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as e:
            raise DecryptionError(f"Invalid UTF-8: {e}")

    async def process_transaction(self, tx: NoteTransaction) -> Optional[Message]:
        """Processes a transaction and extracts any chat message."""
        # Check if this is a chat message
        if not is_chat_message(tx.note):
            return None

        # Determine direction
        if tx.sender == self._address:
            direction = MessageDirection.SENT
        elif tx.receiver == self._address:
            direction = MessageDirection.RECEIVED
        else:
            return None  # Not relevant to us

        # Get the other party's address and key
        if direction == MessageDirection.SENT:
            other_address = tx.receiver
            key = await self.discover_key(tx.receiver)
            if key is None:
                raise PublicKeyNotFoundError(f"Key not found for {tx.receiver}")
            other_key = key.public_key
        else:
            other_address = tx.sender
            key = await self.discover_key(tx.sender)
            if key is None:
                raise PublicKeyNotFoundError(f"Key not found for {tx.sender}")
            other_key = key.public_key

        # Decrypt the message
        content = self.decrypt(tx.note, other_key)

        # Create message
        timestamp = datetime.fromtimestamp(tx.round_time)

        message = Message(
            id=tx.txid,
            sender=tx.sender,
            recipient=tx.receiver,
            content=content,
            timestamp=timestamp,
            confirmed_round=tx.confirmed_round,
            direction=direction,
            reply_context=None,  # Reply context would be parsed from content
        )

        # Update conversation
        async with self._lock:
            conv = None
            for c in self._conversations:
                if c.participant == other_address:
                    conv = c
                    break

            if conv is None:
                conv = Conversation(other_address)
                self._conversations.append(conv)

            conv.append(message)

        # Cache message
        if self._config.cache_messages:
            await self._message_cache.store([message], message.sender)

        return message

    async def sync(self) -> list[Message]:
        """Fetches new messages from the blockchain."""
        all_messages = []

        # Get transactions for our address
        txs = await self._indexer.search_transactions(self._address, limit=100)

        for tx in txs:
            message = await self.process_transaction(tx)
            if message is not None:
                all_messages.append(message)

        return all_messages

    @property
    def send_queue(self) -> SendQueue:
        """Returns the send queue for managing pending messages."""
        return self._send_queue

    @property
    def message_cache(self) -> MessageCache:
        """Returns the message cache."""
        return self._message_cache

    @property
    def public_key_cache(self) -> PublicKeyCache:
        """Returns the public key cache."""
        return self._public_key_cache
