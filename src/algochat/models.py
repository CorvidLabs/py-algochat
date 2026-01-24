"""Models for AlgoChat messages and conversations."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import uuid


class MessageDirection(Enum):
    """Direction of a message relative to the current user."""
    SENT = "sent"
    RECEIVED = "received"


@dataclass
class ReplyContext:
    """Context for a reply message, linking it to the original."""
    message_id: str
    preview: str

    @classmethod
    def from_message(cls, message: "Message", max_length: int = 80) -> "ReplyContext":
        """Creates a reply context from a message, truncating the preview."""
        preview = message.content
        if len(preview) > max_length:
            preview = preview[:max_length - 3] + "..."
        return cls(message_id=message.id, preview=preview)


@dataclass
class Message:
    """A chat message between Algorand addresses."""
    id: str
    sender: str
    recipient: str
    content: str
    timestamp: datetime
    confirmed_round: int
    direction: MessageDirection
    reply_context: Optional[ReplyContext] = None

    def is_reply(self) -> bool:
        """Whether this message is a reply to another message."""
        return self.reply_context is not None

    def unix_timestamp(self) -> int:
        """Returns the Unix timestamp in seconds."""
        return int(self.timestamp.timestamp())


class Conversation:
    """A conversation between two Algorand addresses."""

    def __init__(
        self,
        participant: str,
        participant_encryption_key: Optional[bytes] = None,
    ) -> None:
        """Creates a new conversation."""
        self.participant = participant
        self.participant_encryption_key = participant_encryption_key
        self._messages: list[Message] = []
        self.last_fetched_round: Optional[int] = None

    @property
    def id(self) -> str:
        """Returns the unique identifier (the participant's address)."""
        return self.participant

    @property
    def messages(self) -> list[Message]:
        """Returns all messages in the conversation."""
        return list(self._messages)

    def last_message(self) -> Optional[Message]:
        """Returns the most recent message."""
        return self._messages[-1] if self._messages else None

    def last_received(self) -> Optional[Message]:
        """Returns the most recent received message."""
        for msg in reversed(self._messages):
            if msg.direction == MessageDirection.RECEIVED:
                return msg
        return None

    def last_sent(self) -> Optional[Message]:
        """Returns the most recent sent message."""
        for msg in reversed(self._messages):
            if msg.direction == MessageDirection.SENT:
                return msg
        return None

    def received_messages(self) -> list[Message]:
        """Returns all received messages."""
        return [m for m in self._messages if m.direction == MessageDirection.RECEIVED]

    def sent_messages(self) -> list[Message]:
        """Returns all sent messages."""
        return [m for m in self._messages if m.direction == MessageDirection.SENT]

    def message_count(self) -> int:
        """Returns the number of messages."""
        return len(self._messages)

    def is_empty(self) -> bool:
        """Whether the conversation has any messages."""
        return len(self._messages) == 0

    def append(self, message: Message) -> None:
        """Adds a message to the conversation (maintains chronological order)."""
        if any(m.id == message.id for m in self._messages):
            return
        self._messages.append(message)
        self._messages.sort(key=lambda m: m.timestamp)

    def merge(self, new_messages: list[Message]) -> None:
        """Merges new messages into the conversation."""
        for message in new_messages:
            self.append(message)


@dataclass
class DiscoveredKey:
    """Result of discovering a user's encryption key."""
    public_key: bytes
    is_verified: bool


@dataclass
class SendOptions:
    """Options for sending a message."""
    wait_for_confirmation: bool = False
    timeout_rounds: int = 10
    wait_for_indexer: bool = False
    indexer_timeout_secs: int = 30
    reply_context: Optional[ReplyContext] = None

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

    def with_reply(self, context: ReplyContext) -> "SendOptions":
        """Set the reply context."""
        return SendOptions(
            wait_for_confirmation=self.wait_for_confirmation,
            timeout_rounds=self.timeout_rounds,
            wait_for_indexer=self.wait_for_indexer,
            indexer_timeout_secs=self.indexer_timeout_secs,
            reply_context=context,
        )


@dataclass
class SendResult:
    """Result of a successful send operation."""
    txid: str
    message: Message


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
    recipient: str
    content: str
    reply_context: Optional[ReplyContext]
    created_at: datetime
    retry_count: int = 0
    last_attempt: Optional[datetime] = None
    status: PendingStatus = PendingStatus.PENDING
    last_error: Optional[str] = None

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
            created_at=datetime.now(),
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
