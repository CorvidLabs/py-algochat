"""Data models for AlgoChat.

This module defines the core types for messages, conversations, accounts,
and related structures used throughout the library.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Iterator, List, Optional
import uuid


@dataclass
class ReplyContext:
    """Context for a reply message, linking it to the original."""

    message_id: str
    """Transaction ID of the original message."""

    preview: str
    """Preview of the original message (truncated)."""

    @classmethod
    def from_message(cls, message: "Message", max_length: int = 80) -> "ReplyContext":
        """Creates a reply context from a message, truncating the preview."""
        if len(message.content) > max_length:
            preview = message.content[: max_length - 3] + "..."
        else:
            preview = message.content

        return cls(message_id=message.id, preview=preview)


class MessageDirection(Enum):
    """Direction of a message relative to the current user."""

    SENT = "sent"
    RECEIVED = "received"


@dataclass
class Message:
    """A chat message between Algorand addresses."""

    id: str
    """Unique identifier (transaction ID)."""

    sender: str
    """Sender's Algorand address."""

    recipient: str
    """Recipient's Algorand address."""

    content: str
    """Decrypted message content."""

    timestamp: datetime
    """Timestamp when the message was confirmed on-chain."""

    confirmed_round: int
    """The round in which the transaction was confirmed."""

    direction: MessageDirection
    """Message direction relative to the current user."""

    reply_context: Optional[ReplyContext] = None
    """Reply context if this message is a reply."""

    @property
    def is_reply(self) -> bool:
        """Whether this message is a reply to another message."""
        return self.reply_context is not None

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Message):
            return NotImplemented
        return self.id == other.id


@dataclass
class Conversation:
    """A conversation between two Algorand addresses."""

    participant: str
    """The other party's Algorand address."""

    participant_encryption_key: Optional[bytes] = None
    """Cached encryption public key for the participant (32 bytes)."""

    _messages: List[Message] = field(default_factory=list)
    """Messages in chronological order."""

    last_fetched_round: Optional[int] = None
    """The round of the last fetched message (for pagination)."""

    @property
    def id(self) -> str:
        """Returns the unique identifier (the participant's address)."""
        return self.participant

    @property
    def messages(self) -> List[Message]:
        """Returns all messages in the conversation."""
        return self._messages

    @property
    def last_message(self) -> Optional[Message]:
        """Returns the most recent message."""
        return self._messages[-1] if self._messages else None

    @property
    def last_received(self) -> Optional[Message]:
        """Returns the most recent received message."""
        for msg in reversed(self._messages):
            if msg.direction == MessageDirection.RECEIVED:
                return msg
        return None

    @property
    def last_sent(self) -> Optional[Message]:
        """Returns the most recent sent message."""
        for msg in reversed(self._messages):
            if msg.direction == MessageDirection.SENT:
                return msg
        return None

    @property
    def received_messages(self) -> Iterator[Message]:
        """Returns all received messages."""
        return (m for m in self._messages if m.direction == MessageDirection.RECEIVED)

    @property
    def sent_messages(self) -> Iterator[Message]:
        """Returns all sent messages."""
        return (m for m in self._messages if m.direction == MessageDirection.SENT)

    @property
    def message_count(self) -> int:
        """Returns the number of messages."""
        return len(self._messages)

    @property
    def is_empty(self) -> bool:
        """Whether the conversation has any messages."""
        return len(self._messages) == 0

    def append(self, message: Message) -> None:
        """Adds a message to the conversation (maintains chronological order)."""
        if any(m.id == message.id for m in self._messages):
            return
        self._messages.append(message)
        self._messages.sort(key=lambda m: m.timestamp)

    def merge(self, new_messages: List[Message]) -> None:
        """Merges new messages into the conversation."""
        for message in new_messages:
            self.append(message)


@dataclass
class DiscoveredKey:
    """Result of discovering a user's encryption key."""

    public_key: bytes
    """The X25519 public key (32 bytes)."""

    is_verified: bool
    """Whether the key was cryptographically verified via Ed25519 signature."""


@dataclass
class SendOptions:
    """Options for sending a message."""

    wait_for_confirmation: bool = False
    """Wait for algod confirmation."""

    timeout_rounds: int = 10
    """Maximum rounds to wait for confirmation."""

    wait_for_indexer: bool = False
    """Wait for indexer visibility."""

    indexer_timeout_secs: int = 30
    """Maximum seconds to wait for indexer."""

    reply_context: Optional[ReplyContext] = None
    """Reply context if replying to a message."""

    @classmethod
    def fire_and_forget(cls) -> "SendOptions":
        """Fire-and-forget (no waiting)."""
        return cls()

    @classmethod
    def confirmed(cls) -> "SendOptions":
        """Wait for algod confirmation only."""
        return cls(wait_for_confirmation=True)

    @classmethod
    def indexed(cls) -> "SendOptions":
        """Wait for both algod and indexer."""
        return cls(wait_for_confirmation=True, wait_for_indexer=True)

    @classmethod
    def replying_to(cls, message: Message) -> "SendOptions":
        """Create options for replying to a message."""
        return cls(reply_context=ReplyContext.from_message(message))


@dataclass
class SendResult:
    """Result of a successful send operation."""

    txid: str
    """Transaction ID."""

    message: Message
    """The sent message (for optimistic UI updates)."""


class PendingStatus(Enum):
    """Status of a pending message in the send queue."""

    PENDING = "pending"
    SENDING = "sending"
    FAILED = "failed"
    SENT = "sent"


@dataclass
class PendingMessage:
    """A message queued for sending (for offline support)."""

    id: str
    """Unique identifier."""

    recipient: str
    """Recipient's Algorand address."""

    content: str
    """Message content."""

    reply_context: Optional[ReplyContext] = None
    """Reply context if replying."""

    created_at: datetime = field(default_factory=datetime.now)
    """When the message was created."""

    retry_count: int = 0
    """Number of retry attempts."""

    last_attempt: Optional[datetime] = None
    """Last attempt time."""

    status: PendingStatus = PendingStatus.PENDING
    """Current status."""

    last_error: Optional[str] = None
    """Last error message."""

    @classmethod
    def create(
        cls,
        recipient: str,
        content: str,
        reply_context: Optional[ReplyContext] = None,
    ) -> "PendingMessage":
        """Creates a new pending message."""
        return cls(
            id=str(uuid.uuid4()),
            recipient=recipient,
            content=content,
            reply_context=reply_context,
        )

    def mark_sending(self) -> None:
        """Mark as currently sending."""
        self.status = PendingStatus.SENDING
        self.last_attempt = datetime.now()

    def mark_failed(self, error: str) -> None:
        """Mark as failed with an error."""
        self.status = PendingStatus.FAILED
        self.retry_count += 1
        self.last_error = error

    def mark_sent(self) -> None:
        """Mark as successfully sent."""
        self.status = PendingStatus.SENT

    def can_retry(self, max_retries: int) -> bool:
        """Whether the message can be retried."""
        return self.retry_count < max_retries and self.status == PendingStatus.FAILED
