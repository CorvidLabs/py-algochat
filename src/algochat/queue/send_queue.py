"""Send queue for managing pending outgoing messages."""

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from ..models import PendingMessage, PendingStatus


@dataclass
class QueueConfig:
    """Configuration for the send queue."""
    max_retries: int = 3
    retry_delay: timedelta = timedelta(seconds=5)
    max_queue_size: int = 100


class QueueFullError(Exception):
    """Error thrown when the queue is full."""

    def __init__(self) -> None:
        super().__init__("Queue is full")


class MessageNotFoundError(Exception):
    """Error thrown when a message is not found."""

    def __init__(self, message_id: str) -> None:
        super().__init__(f"Message not found: {message_id}")
        self.message_id = message_id


class SendQueue:
    """A queue for managing pending outgoing messages."""

    def __init__(self, config: Optional[QueueConfig] = None) -> None:
        """Creates a new send queue with the given configuration."""
        self._queue: deque[PendingMessage] = deque()
        self._config = config or QueueConfig()

    async def enqueue(self, message: PendingMessage) -> None:
        """Enqueues a new message for sending."""
        if len(self._queue) >= self._config.max_queue_size:
            # Remove oldest failed messages that can't be retried
            self._queue = deque(
                m for m in self._queue
                if m.status != PendingStatus.FAILED or m.can_retry(self._config.max_retries)
            )

            if len(self._queue) >= self._config.max_queue_size:
                raise QueueFullError()

        self._queue.append(message)

    async def next_pending(self) -> Optional[PendingMessage]:
        """Returns the next message ready for sending."""
        for msg in self._queue:
            if msg.status == PendingStatus.PENDING:
                return msg
        return None

    async def all_pending(self) -> list[PendingMessage]:
        """Returns all pending messages."""
        return [m for m in self._queue if m.status == PendingStatus.PENDING]

    async def ready_for_retry(self) -> list[PendingMessage]:
        """Returns messages ready for retry."""
        now = datetime.now()
        result = []

        for msg in self._queue:
            if not msg.can_retry(self._config.max_retries):
                continue

            if msg.last_attempt is None:
                result.append(msg)
            elif now - msg.last_attempt >= self._config.retry_delay:
                result.append(msg)

        return result

    async def mark_sending(self, message_id: str) -> None:
        """Marks a message as currently sending."""
        msg = self._find_message(message_id)
        if msg is None:
            raise MessageNotFoundError(message_id)
        msg.mark_sending()

    async def mark_sent(self, message_id: str) -> None:
        """Marks a message as successfully sent."""
        msg = self._find_message(message_id)
        if msg is None:
            raise MessageNotFoundError(message_id)
        msg.mark_sent()

    async def mark_failed(self, message_id: str, error: str) -> None:
        """Marks a message as failed with an error."""
        msg = self._find_message(message_id)
        if msg is None:
            raise MessageNotFoundError(message_id)
        msg.mark_failed(error)

    async def remove(self, message_id: str) -> Optional[PendingMessage]:
        """Removes a message from the queue."""
        for i, msg in enumerate(self._queue):
            if msg.id == message_id:
                del self._queue[i]
                return msg
        return None

    async def prune_sent(self) -> None:
        """Removes all sent messages from the queue."""
        self._queue = deque(m for m in self._queue if m.status != PendingStatus.SENT)

    async def prune_failed(self) -> None:
        """Removes all messages that have exceeded max retries."""
        self._queue = deque(
            m for m in self._queue
            if m.status != PendingStatus.FAILED or m.can_retry(self._config.max_retries)
        )

    async def clear(self) -> None:
        """Clears all messages from the queue."""
        self._queue.clear()

    @property
    def length(self) -> int:
        """Returns the number of messages in the queue."""
        return len(self._queue)

    @property
    def is_empty(self) -> bool:
        """Returns true if the queue is empty."""
        return len(self._queue) == 0

    async def pending_count(self) -> int:
        """Returns the number of pending messages."""
        return sum(1 for m in self._queue if m.status == PendingStatus.PENDING)

    async def failed_count(self) -> int:
        """Returns the number of failed messages."""
        return sum(1 for m in self._queue if m.status == PendingStatus.FAILED)

    async def messages_for(self, recipient: str) -> list[PendingMessage]:
        """Returns messages for a specific recipient."""
        return [m for m in self._queue if m.recipient == recipient]

    async def reset_for_retry(self, message_id: str) -> None:
        """Resets a failed message to pending status for retry."""
        msg = self._find_message(message_id)
        if msg is None:
            raise MessageNotFoundError(message_id)

        if not msg.can_retry(self._config.max_retries):
            raise ValueError("Message has exceeded max retries")

        msg.status = PendingStatus.PENDING

    def _find_message(self, message_id: str) -> Optional[PendingMessage]:
        """Find a message by ID."""
        for msg in self._queue:
            if msg.id == message_id:
                return msg
        return None
