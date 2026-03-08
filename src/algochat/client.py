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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .crypto import encrypt_message, decrypt_message
from .envelope import encode_envelope, decode_envelope, is_chat_message
from .keys import derive_keys_from_seed, public_key_from_bytes
from .models import (
    Conversation,
    DiscoveredKey,
    Message,
    MessageDirection,
    PSKContact,
)
from .psk_crypto import encrypt_psk_message, decrypt_psk_message
from .psk_envelope import encode_psk_envelope, decode_psk_envelope, is_psk_message
from .psk_ratchet import derive_psk_at_counter
from .psk_state import PSKState, validate_counter, record_receive, advance_send_counter
from .psk_exchange import create_psk_exchange_uri, parse_psk_exchange_uri
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
    PSKEncryptionError,
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
        encryption_private_key: X25519PrivateKey,
        encryption_public_key: X25519PublicKey,
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
        self._psk_contacts: dict[str, PSKContact] = {}
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

        # Derive the Ed25519 public key from the seed (private key)
        ed25519_private = Ed25519PrivateKey.from_private_bytes(seed)
        ed25519_public_key = ed25519_private.public_key().public_bytes_raw()

        return cls(
            address=address,
            ed25519_public_key=ed25519_public_key,
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

    # --- PSK Contact Management ---

    def add_psk_contact(
        self, address: str, psk: bytes, label: Optional[str] = None
    ) -> PSKContact:
        """Register a PSK contact for encrypted messaging.

        Args:
            address: The contact's Algorand address.
            psk: The pre-shared key (32 bytes).
            label: Optional human-readable label.

        Returns:
            The created PSKContact.
        """
        if len(psk) != 32:
            raise ValueError("PSK must be 32 bytes")

        contact = PSKContact(address=address, initial_psk=psk, label=label)
        self._psk_contacts[address] = contact
        return contact

    def add_psk_contact_from_uri(self, uri: str) -> PSKContact:
        """Register a PSK contact from an exchange URI.

        Args:
            uri: The PSK exchange URI (algochat-psk://v1?...).

        Returns:
            The created PSKContact.
        """
        parsed = parse_psk_exchange_uri(uri)
        return self.add_psk_contact(
            address=parsed["address"],
            psk=parsed["psk"],
            label=parsed.get("label"),
        )

    def remove_psk_contact(self, address: str) -> bool:
        """Remove a PSK contact.

        Returns:
            True if the contact was removed, False if not found.
        """
        return self._psk_contacts.pop(address, None) is not None

    def get_psk_contact(self, address: str) -> Optional[PSKContact]:
        """Get a PSK contact by address."""
        return self._psk_contacts.get(address)

    @property
    def psk_contacts(self) -> list[PSKContact]:
        """Returns all PSK contacts."""
        return list(self._psk_contacts.values())

    def create_psk_exchange_uri(
        self, psk: bytes, label: Optional[str] = None
    ) -> str:
        """Create a PSK exchange URI for sharing with a contact.

        Args:
            psk: The pre-shared key (32 bytes).
            label: Optional human-readable label.

        Returns:
            The PSK exchange URI string.
        """
        return create_psk_exchange_uri(self._address, psk, label)

    # --- Standard Encryption ---

    def encrypt(self, message: str, recipient_public_key: bytes) -> bytes:
        """Encrypts a message for a recipient."""
        from .keys import public_key_from_bytes

        recipient_key = public_key_from_bytes(recipient_public_key)

        envelope = encrypt_message(
            message,
            self._encryption_private_key,
            self._encryption_public_key,
            recipient_key,
        )

        return encode_envelope(envelope)

    def decrypt(self, envelope: bytes, sender_public_key: bytes) -> str:
        """Decrypts a message from a sender."""
        if not is_chat_message(envelope):
            raise InvalidEnvelopeError("Not an AlgoChat message")

        decoded = decode_envelope(envelope)

        result = decrypt_message(
            decoded,
            self._encryption_private_key,
            self._encryption_public_key,
        )

        if result is None:
            # Key-publish payload
            return ""

        return result.text

    # --- PSK Encryption ---

    def encrypt_psk(self, message: str, recipient_address: str, recipient_public_key: bytes) -> bytes:
        """Encrypt a message using PSK v1.1 protocol.

        Automatically manages the ratchet counter for the contact.

        Args:
            message: The message to encrypt.
            recipient_address: The recipient's Algorand address.
            recipient_public_key: The recipient's X25519 public key (32 bytes).

        Returns:
            Encoded PSK envelope bytes.

        Raises:
            PSKEncryptionError: If no PSK contact exists for the address.
        """
        contact = self._psk_contacts.get(recipient_address)
        if contact is None:
            raise PSKEncryptionError(
                f"No PSK contact for {recipient_address}"
            )

        recipient_key = public_key_from_bytes(recipient_public_key)

        # Advance counter
        state = PSKState(
            send_counter=contact.send_counter,
            peer_last_counter=contact.peer_last_counter,
            seen_counters=set(contact.seen_counters),
        )
        counter, new_state = advance_send_counter(state)
        contact.send_counter = new_state.send_counter

        # Derive PSK for this counter
        current_psk = derive_psk_at_counter(contact.initial_psk, counter)

        envelope = encrypt_psk_message(
            message,
            self._encryption_private_key,
            self._encryption_public_key,
            recipient_key,
            current_psk,
            counter,
        )

        return encode_psk_envelope(envelope)

    def decrypt_psk(self, data: bytes, sender_address: str) -> str:
        """Decrypt a PSK v1.1 protocol message.

        Validates the ratchet counter and updates contact state.

        Args:
            data: The encoded PSK envelope bytes.
            sender_address: The sender's Algorand address.

        Returns:
            Decrypted message text.

        Raises:
            PSKDecryptionError: If decryption or counter validation fails.
        """
        from .types import PSKDecryptionError

        contact = self._psk_contacts.get(sender_address)
        if contact is None:
            raise PSKDecryptionError(
                f"No PSK contact for {sender_address}"
            )

        envelope = decode_psk_envelope(data)

        # Validate counter
        state = PSKState(
            send_counter=contact.send_counter,
            peer_last_counter=contact.peer_last_counter,
            seen_counters=set(contact.seen_counters),
        )
        if not validate_counter(state, envelope.ratchet_counter):
            raise PSKDecryptionError(
                f"Invalid ratchet counter: {envelope.ratchet_counter}"
            )

        # Derive PSK for this counter
        current_psk = derive_psk_at_counter(
            contact.initial_psk, envelope.ratchet_counter
        )

        result = decrypt_psk_message(
            envelope,
            self._encryption_private_key,
            self._encryption_public_key,
            current_psk,
        )

        # Update contact state after successful decryption
        new_state = record_receive(state, envelope.ratchet_counter)
        contact.peer_last_counter = new_state.peer_last_counter
        contact.seen_counters = new_state.seen_counters

        return result

    async def process_transaction(self, tx: NoteTransaction) -> Optional[Message]:
        """Processes a transaction and extracts any chat message.

        Automatically detects whether the message uses standard or PSK protocol.
        """
        is_standard = is_chat_message(tx.note)
        is_psk = is_psk_message(tx.note)

        if not is_standard and not is_psk:
            return None

        # Determine direction
        if tx.sender == self._address:
            direction = MessageDirection.SENT
        elif tx.receiver == self._address:
            direction = MessageDirection.RECEIVED
        else:
            return None  # Not relevant to us

        # Get the other party's address
        other_address = tx.receiver if direction == MessageDirection.SENT else tx.sender

        # Decrypt based on protocol type
        if is_psk:
            # PSK messages use the contact's PSK for decryption
            content = self.decrypt_psk(tx.note, other_address)
        else:
            # Standard messages need the other party's public key
            key = await self.discover_key(other_address)
            if key is None:
                raise PublicKeyNotFoundError(f"Key not found for {other_address}")
            content = self.decrypt(tx.note, key.public_key)

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
