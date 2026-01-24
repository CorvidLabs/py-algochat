"""
Message queue for offline message support.

This module provides a queue for managing pending outgoing messages,
supporting offline message composition and automatic retry.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional
import asyncio

from .models import PendingMessage, PendingStatus


@dataclass
class QueueConfig:
    """Configuration for the send queue."""

    max_retries: int = 3
    """Maximum number of retry attempts."""

    retry_delay: timedelta = field(default_factory=lambda: timedelta(seconds=5))
    """Delay between retry attempts."""

    max_queue_size: int = 100
    """Maximum queue size."""


class SendQueue:
    """A queue for managing pending outgoing messages."""

    def __init__(self, config: Optional[QueueConfig] = None) -> None:
        self._queue: list[PendingMessage] = []
        self._config = config or QueueConfig()
        self._lock = asyncio.Lock()

    @property
    def config(self) -> QueueConfig:
        """Returns the queue configuration."""
        return self._config

    async def enqueue(self, message: PendingMessage) -> None:
        """Enqueues a new message for sending."""
        async with self._lock:
            if len(self._queue) >= self._config.max_queue_size:
                # Remove oldest failed messages to make room
                self._queue = [
                    m for m in self._queue
                    if m.status != PendingStatus.FAILED or m.can_retry(self._config.max_retries)
                ]

                if len(self._queue) >= self._config.max_queue_size:
                    raise RuntimeError("Queue is full")

            self._queue.append(message)

    async def next_pending(self) -> Optional[PendingMessage]:
        """Returns the next message ready for sending."""
        async with self._lock:
            for msg in self._queue:
                if msg.status == PendingStatus.PENDING:
                    return msg
            return None

    async def all_pending(self) -> list[PendingMessage]:
        """Returns all pending messages."""
        async with self._lock:
            return [m for m in self._queue if m.status == PendingStatus.PENDING]

    async def ready_for_retry(self) -> list[PendingMessage]:
        """Returns messages ready for retry."""
        async with self._lock:
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
        async with self._lock:
            for msg in self._queue:
                if msg.id == message_id:
                    msg.mark_sending()
                    return
            raise KeyError(f"Message not found: {message_id}")

    async def mark_sent(self, message_id: str) -> None:
        """Marks a message as successfully sent."""
        async with self._lock:
            for msg in self._queue:
                if msg.id == message_id:
                    msg.mark_sent()
                    return
            raise KeyError(f"Message not found: {message_id}")

    async def mark_failed(self, message_id: str, error: str) -> None:
        """Marks a message as failed with an error."""
        async with self._lock:
            for msg in self._queue:
                if msg.id == message_id:
                    msg.mark_failed(error)
                    return
            raise KeyError(f"Message not found: {message_id}")

    async def remove(self, message_id: str) -> Optional[PendingMessage]:
        """Removes a message from the queue."""
        async with self._lock:
            for i, msg in enumerate(self._queue):
                if msg.id == message_id:
                    return self._queue.pop(i)
            return None

    async def prune_sent(self) -> None:
        """Removes all sent messages from the queue."""
        async with self._lock:
            self._queue = [m for m in self._queue if m.status != PendingStatus.SENT]

    async def prune_failed(self) -> None:
        """Removes all messages that have exceeded max retries."""
        async with self._lock:
            self._queue = [
                m for m in self._queue
                if m.status != PendingStatus.FAILED or m.can_retry(self._config.max_retries)
            ]

    async def clear(self) -> None:
        """Clears all messages from the queue."""
        async with self._lock:
            self._queue.clear()

    async def __len__(self) -> int:
        """Returns the number of messages in the queue."""
        async with self._lock:
            return len(self._queue)

    async def is_empty(self) -> bool:
        """Returns true if the queue is empty."""
        async with self._lock:
            return len(self._queue) == 0

    async def pending_count(self) -> int:
        """Returns the number of pending messages."""
        async with self._lock:
            return sum(1 for m in self._queue if m.status == PendingStatus.PENDING)

    async def failed_count(self) -> int:
        """Returns the number of failed messages."""
        async with self._lock:
            return sum(1 for m in self._queue if m.status == PendingStatus.FAILED)

    async def messages_for(self, recipient: str) -> list[PendingMessage]:
        """Returns messages for a specific recipient."""
        async with self._lock:
            return [m for m in self._queue if m.recipient == recipient]

    async def reset_for_retry(self, message_id: str) -> None:
        """Resets a failed message to pending status for retry."""
        async with self._lock:
            for msg in self._queue:
                if msg.id == message_id:
                    if msg.can_retry(self._config.max_retries):
                        msg.status = PendingStatus.PENDING
                        return
                    else:
                        raise RuntimeError("Message has exceeded max retries")
            raise KeyError(f"Message not found: {message_id}")
