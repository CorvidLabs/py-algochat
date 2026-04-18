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
)
from .psk_crypto import encrypt_psk_message, decrypt_psk_message
from .psk_envelope import encode_psk_envelope, decode_psk_envelope, is_psk_message
from .psk_ratchet import derive_psk_at_counter
from .psk_state import PSKState, validate_counter, record_receive, advance_send_counter
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
    PSKDecryptionError,
    PublicKeyNotFoundError,
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
        self._lock = asyncio.Lock()
        self._psk_channels: dict[str, tuple[bytes, PSKState]] = {}  # address -> (psk, state)
        self._pubkey_to_address: dict[str, str] = {}  # pubkey_hex -> address

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
        if key is not None:
            self._pubkey_to_address[key.public_key.hex()] = address
            if self._config.cache_public_keys:
                await self._public_key_cache.store(address, key.public_key)

        return key

    def encrypt(
        self,
        message: str,
        recipient_public_key: bytes,
        psk: Optional[bytes] = None,
    ) -> bytes:
        """Encrypts a message for a recipient.

        Args:
            message: The plaintext message.
            recipient_public_key: Recipient's X25519 public key (32 bytes).
            psk: Optional pre-shared key (32 bytes). If provided, uses PSK v1.1 protocol.

        Returns:
            Encoded envelope bytes.
        """
        recipient_key = public_key_from_bytes(recipient_public_key)

        if psk is not None:
            # Use PSK v1.1 protocol
            recipient_address = self._address_for_key(recipient_public_key)
            state = self._get_psk_state(recipient_address, psk)
            counter, new_state = advance_send_counter(state)
            current_psk = derive_psk_at_counter(psk, counter)

            envelope = encrypt_psk_message(
                message,
                self._encryption_private_key,
                self._encryption_public_key,
                recipient_key,
                current_psk,
                counter,
            )

            self._set_psk_state(recipient_address, psk, new_state)
            return encode_psk_envelope(envelope)

        envelope = encrypt_message(
            message,
            self._encryption_private_key,
            self._encryption_public_key,
            recipient_key,
        )

        return encode_envelope(envelope)

    def decrypt(
        self,
        envelope_bytes: bytes,
        sender_public_key: bytes = b"",
        psk: Optional[bytes] = None,
    ) -> str:
        """Decrypts a message.

        Automatically detects whether the envelope uses standard v1 or PSK v1.1 protocol.

        Args:
            envelope_bytes: The encoded envelope bytes.
            sender_public_key: Sender's public key (only needed for standard v1).
            psk: Optional pre-shared key (32 bytes). Required if envelope is PSK v1.1.

        Returns:
            Decrypted message text.
        """
        if is_psk_message(envelope_bytes):
            return self._decrypt_psk(envelope_bytes, psk)

        if not is_chat_message(envelope_bytes):
            raise InvalidEnvelopeError("Not an AlgoChat message")

        decoded = decode_envelope(envelope_bytes)

        result = decrypt_message(
            decoded,
            self._encryption_private_key,
            self._encryption_public_key,
        )

        if result is None:
            # Key-publish payload
            return ""

        return result.text

    def _decrypt_psk(self, envelope_bytes: bytes, psk: Optional[bytes] = None) -> str:
        """Decrypt a PSK v1.1 envelope."""
        decoded = decode_psk_envelope(envelope_bytes)

        # Look up PSK from channel state if not provided
        if psk is None:
            sender_address = self._address_for_key(decoded.sender_public_key)
            channel = self._psk_channels.get(sender_address)
            if channel is not None:
                psk = channel[0]

        if psk is None:
            raise PSKDecryptionError("No PSK available for this message")

        # Validate counter
        sender_address = self._address_for_key(decoded.sender_public_key)
        state = self._get_psk_state(sender_address, psk)

        if not validate_counter(state, decoded.ratchet_counter):
            raise PSKDecryptionError(
                f"Invalid counter: {decoded.ratchet_counter} (replay or out of window)"
            )

        current_psk = derive_psk_at_counter(psk, decoded.ratchet_counter)

        result = decrypt_psk_message(
            decoded,
            self._encryption_private_key,
            self._encryption_public_key,
            current_psk,
        )

        # Record successful receive
        new_state = record_receive(state, decoded.ratchet_counter)
        self._set_psk_state(sender_address, psk, new_state)

        return result

    # --- PSK channel management ---

    def add_psk_channel(self, address: str, psk: bytes) -> None:
        """Register a PSK channel for a participant.

        Args:
            address: The participant's Algorand address.
            psk: The pre-shared key (32 bytes).
        """
        if len(psk) != 32:
            raise ValueError("PSK must be 32 bytes")
        self._psk_channels[address] = (psk, PSKState())

    def remove_psk_channel(self, address: str) -> None:
        """Remove a PSK channel."""
        self._psk_channels.pop(address, None)

    def has_psk_channel(self, address: str) -> bool:
        """Check if a PSK channel exists for an address."""
        return address in self._psk_channels

    def get_psk_state(self, address: str) -> Optional[PSKState]:
        """Get the PSK state for a channel (for inspection/persistence)."""
        channel = self._psk_channels.get(address)
        if channel is not None:
            return channel[1]
        return None

    def rotate_psk(self, address: str, new_psk: bytes) -> None:
        """Rotate the PSK for a channel, preserving counter state.

        Args:
            address: The participant's Algorand address.
            new_psk: The new pre-shared key (32 bytes).
        """
        if len(new_psk) != 32:
            raise ValueError("PSK must be 32 bytes")
        self._psk_channels[address] = (new_psk, PSKState())

    def _get_psk_state(self, address: str, psk: bytes) -> PSKState:
        """Get or create PSK state for an address."""
        channel = self._psk_channels.get(address)
        if channel is not None and channel[0] == psk:
            return channel[1]
        return PSKState()

    def _set_psk_state(self, address: str, psk: bytes, state: PSKState) -> None:
        """Update PSK state for an address."""
        self._psk_channels[address] = (psk, state)

    def _address_for_key(self, public_key: bytes) -> str:
        """Look up address for a public key, or use key hex as fallback."""
        return self._pubkey_to_address.get(public_key.hex(), public_key.hex())

    async def process_transaction(self, tx: NoteTransaction) -> Optional[Message]:
        """Processes a transaction and extracts any chat message."""
        # Check if this is a chat message (standard or PSK)
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

        # Get the other party's address and key
        if direction == MessageDirection.SENT:
            other_address = tx.receiver
        else:
            other_address = tx.sender

        if is_standard:
            key = await self.discover_key(other_address)
            if key is None:
                raise PublicKeyNotFoundError(f"Key not found for {other_address}")
            other_key = key.public_key
        else:
            other_key = b""  # PSK envelopes carry their own sender key
            # Register pubkey→address from the PSK envelope header
            decoded_env = decode_psk_envelope(tx.note)
            self._pubkey_to_address[decoded_env.sender_public_key.hex()] = tx.sender

        # Decrypt the message — auto-detects PSK vs standard
        psk = None
        if is_psk:
            channel = self._psk_channels.get(other_address)
            if channel is not None:
                psk = channel[0]
        content = self.decrypt(tx.note, other_key, psk=psk)

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
