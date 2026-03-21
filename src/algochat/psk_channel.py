"""High-level PSK channel for managing encrypted conversations.

A PSKChannel wraps a single pre-shared key relationship between two parties,
managing ratchet state, counter validation, encryption, and decryption.
Equivalent to PSKManager in ts-algochat.
"""

import os
import time
from dataclasses import dataclass, field
from typing import Optional, Callable, List

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .keys import public_key_to_bytes, public_key_from_bytes
from .psk_types import PSKEnvelope, PSK_SESSION_SIZE
from .psk_ratchet import derive_psk_at_counter
from .psk_crypto import encrypt_psk_message, decrypt_psk_message
from .psk_envelope import encode_psk_envelope, decode_psk_envelope, is_psk_message
from .psk_state import PSKState, validate_counter, record_receive, advance_send_counter
from .psk_exchange import create_psk_exchange_uri, parse_psk_exchange_uri
from .types import PSKEncryptionError, PSKDecryptionError


@dataclass
class PSKMessage:
    """A decrypted PSK message with metadata."""

    text: str
    counter: int
    sender_public_key: bytes
    timestamp: float = field(default_factory=time.time)


@dataclass
class PSKRotationInfo:
    """Information about a PSK rotation in progress."""

    old_psk: bytes
    new_psk: bytes
    grace_deadline: float  # Unix timestamp when old PSK expires


class PSKChannel:
    """Manages a PSK-encrypted conversation with a single contact.

    Handles ratchet state, counter validation, key rotation with grace period,
    and encrypt/decrypt operations for one peer.

    Example::

        channel = PSKChannel(
            initial_psk=shared_secret,
            our_private_key=private_key,
            our_public_key=public_key,
        )

        # Encrypt a message
        envelope_bytes = channel.encrypt("Hello!")

        # Decrypt a received message
        text = channel.decrypt(envelope_bytes)

        # Rotate key with 60-second grace period
        channel.rotate_psk(new_psk, grace_period=60.0)
    """

    def __init__(
        self,
        initial_psk: bytes,
        our_private_key: X25519PrivateKey,
        our_public_key: X25519PublicKey,
        peer_public_key: Optional[X25519PublicKey] = None,
        state: Optional[PSKState] = None,
    ) -> None:
        """Create a new PSK channel.

        Args:
            initial_psk: The initial pre-shared key (32 bytes).
            our_private_key: Our X25519 private key.
            our_public_key: Our X25519 public key.
            peer_public_key: The peer's X25519 public key (can be set later).
            state: Optional initial PSK state (for restoring from persistence).
        """
        if len(initial_psk) != 32:
            raise ValueError(f"PSK must be 32 bytes, got {len(initial_psk)}")

        self._psk = initial_psk
        self._our_private_key = our_private_key
        self._our_public_key = our_public_key
        self._peer_public_key = peer_public_key
        self._state = state if state is not None else PSKState()
        self._rotation: Optional[PSKRotationInfo] = None
        self._seen_txids: set = set()
        self._message_callbacks: List[Callable[[PSKMessage], None]] = []

    @classmethod
    def from_exchange_uri(
        cls,
        uri: str,
        our_private_key: X25519PrivateKey,
        our_public_key: X25519PublicKey,
    ) -> "PSKChannel":
        """Create a PSK channel from an exchange URI.

        Args:
            uri: The algochat-psk:// URI string.
            our_private_key: Our X25519 private key.
            our_public_key: Our X25519 public key.

        Returns:
            A new PSKChannel configured with the PSK from the URI.
        """
        parsed = parse_psk_exchange_uri(uri)
        return cls(
            initial_psk=parsed["psk"],
            our_private_key=our_private_key,
            our_public_key=our_public_key,
        )

    @property
    def psk(self) -> bytes:
        """The current pre-shared key."""
        return self._psk

    @property
    def state(self) -> PSKState:
        """The current counter state (for persistence)."""
        return self._state

    @property
    def peer_public_key(self) -> Optional[X25519PublicKey]:
        """The peer's public key, if known."""
        return self._peer_public_key

    @peer_public_key.setter
    def peer_public_key(self, key: X25519PublicKey) -> None:
        """Set the peer's public key."""
        self._peer_public_key = key

    @property
    def is_in_grace_period(self) -> bool:
        """Whether a PSK rotation grace period is active."""
        if self._rotation is None:
            return False
        return time.time() < self._rotation.grace_deadline

    @property
    def send_counter(self) -> int:
        """The next send counter value."""
        return self._state.send_counter

    @property
    def peer_last_counter(self) -> int:
        """The highest counter received from the peer."""
        return self._state.peer_last_counter

    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt a message and advance the send counter.

        Args:
            plaintext: The message text to encrypt.

        Returns:
            Encoded PSK envelope bytes ready for transmission.

        Raises:
            PSKEncryptionError: If encryption fails.
            ValueError: If peer public key is not set.
        """
        if self._peer_public_key is None:
            raise ValueError("Peer public key must be set before encrypting")

        # Advance counter
        counter, new_state = advance_send_counter(self._state)
        self._state = new_state

        # Derive PSK for this counter
        current_psk = derive_psk_at_counter(self._psk, counter)

        # Encrypt
        envelope = encrypt_psk_message(
            plaintext,
            self._our_private_key,
            self._our_public_key,
            self._peer_public_key,
            current_psk,
            counter,
        )

        return encode_psk_envelope(envelope)

    def decrypt(self, data: bytes, txid: Optional[str] = None) -> PSKMessage:
        """Decrypt a received PSK message.

        Validates the counter, derives the correct PSK, decrypts, and
        updates state. During a grace period, falls back to the old PSK
        if the new one fails.

        Args:
            data: Encoded PSK envelope bytes.
            txid: Optional transaction ID for deduplication.

        Returns:
            PSKMessage with decrypted text and metadata.

        Raises:
            PSKDecryptionError: If decryption fails.
            ValueError: If counter is invalid or message is a replay.
        """
        # Dedup check
        if txid is not None and txid in self._seen_txids:
            raise ValueError(f"Duplicate transaction: {txid}")

        # Decode envelope
        envelope = decode_psk_envelope(data)

        # Validate counter
        if not validate_counter(self._state, envelope.ratchet_counter):
            raise ValueError(
                f"Invalid counter {envelope.ratchet_counter} "
                f"(peer_last={self._state.peer_last_counter})"
            )

        # Learn peer public key from first message if not set
        if self._peer_public_key is None:
            self._peer_public_key = public_key_from_bytes(envelope.sender_public_key)

        # Try decryption with current PSK
        current_psk = derive_psk_at_counter(self._psk, envelope.ratchet_counter)

        try:
            text = decrypt_psk_message(
                envelope,
                self._our_private_key,
                self._our_public_key,
                current_psk,
            )
        except Exception:
            # If in grace period, try old PSK
            if self._rotation is not None and time.time() < self._rotation.grace_deadline:
                old_psk = derive_psk_at_counter(
                    self._rotation.old_psk, envelope.ratchet_counter
                )
                try:
                    text = decrypt_psk_message(
                        envelope,
                        self._our_private_key,
                        self._our_public_key,
                        old_psk,
                    )
                except Exception as e:
                    raise PSKDecryptionError(
                        f"Decryption failed with both new and old PSK: {e}"
                    ) from e
            else:
                raise

        # Update state
        self._state = record_receive(self._state, envelope.ratchet_counter)

        if txid is not None:
            self._seen_txids.add(txid)

        msg = PSKMessage(
            text=text,
            counter=envelope.ratchet_counter,
            sender_public_key=envelope.sender_public_key,
        )

        # Notify callbacks
        for cb in self._message_callbacks:
            cb(msg)

        return msg

    def rotate_psk(self, new_psk: bytes, grace_period: float = 60.0) -> None:
        """Rotate to a new PSK with a grace period.

        During the grace period, decryption will try the new PSK first,
        then fall back to the old one for in-flight messages.

        Args:
            new_psk: The new pre-shared key (32 bytes).
            grace_period: Seconds to keep old PSK valid (default 60).
        """
        if len(new_psk) != 32:
            raise ValueError(f"PSK must be 32 bytes, got {len(new_psk)}")

        self._rotation = PSKRotationInfo(
            old_psk=self._psk,
            new_psk=new_psk,
            grace_deadline=time.time() + grace_period,
        )
        self._psk = new_psk

    def reset(self, new_psk: Optional[bytes] = None) -> None:
        """Hard reset the channel state.

        Clears all counters, seen transactions, and optionally sets a new PSK.

        Args:
            new_psk: Optional new PSK (keeps current if not provided).
        """
        if new_psk is not None:
            if len(new_psk) != 32:
                raise ValueError(f"PSK must be 32 bytes, got {len(new_psk)}")
            self._psk = new_psk

        self._state = PSKState()
        self._rotation = None
        self._seen_txids.clear()

    def generate_exchange_uri(self, address: str, label: Optional[str] = None) -> str:
        """Generate a PSK exchange URI for sharing with the peer.

        Args:
            address: Our Algorand address.
            label: Optional human-readable label.

        Returns:
            The algochat-psk:// URI string.
        """
        return create_psk_exchange_uri(address, self._psk, label)

    def on_message(self, callback: Callable[[PSKMessage], None]) -> None:
        """Register a callback for received messages.

        Args:
            callback: Function called with each decrypted PSKMessage.
        """
        self._message_callbacks.append(callback)

    def off_message(self, callback: Callable[[PSKMessage], None]) -> None:
        """Unregister a message callback.

        Args:
            callback: The callback to remove.
        """
        try:
            self._message_callbacks.remove(callback)
        except ValueError:
            pass

    @staticmethod
    def generate_psk() -> bytes:
        """Generate a random 32-byte PSK.

        Returns:
            32 bytes of cryptographically secure random data.
        """
        return os.urandom(32)

    @staticmethod
    def is_psk_data(data: bytes) -> bool:
        """Check if data is a PSK envelope.

        Args:
            data: Bytes to check.

        Returns:
            True if data appears to be a PSK envelope.
        """
        return is_psk_message(data)
