"""Message cache interface and implementations."""

from abc import ABC, abstractmethod
from typing import Optional

from ..models import Message


class MessageCache(ABC):
    """Interface for storing and retrieving messages."""

    @abstractmethod
    async def store(self, messages: list[Message], participant: str) -> None:
        """Store messages for a conversation."""
        ...

    @abstractmethod
    async def retrieve(
        self,
        participant: str,
        after_round: Optional[int] = None,
    ) -> list[Message]:
        """Retrieve cached messages for a conversation."""
        ...

    @abstractmethod
    async def get_last_sync_round(self, participant: str) -> Optional[int]:
        """Get the last synced round for a conversation."""
        ...

    @abstractmethod
    async def set_last_sync_round(self, round: int, participant: str) -> None:
        """Set the last synced round for a conversation."""
        ...

    @abstractmethod
    async def get_cached_conversations(self) -> list[str]:
        """Get all cached conversation participants."""
        ...

    @abstractmethod
    async def clear(self) -> None:
        """Clear all cached data."""
        ...

    @abstractmethod
    async def clear_for(self, participant: str) -> None:
        """Clear cached data for a specific conversation."""
        ...


class InMemoryMessageCache(MessageCache):
    """In-memory implementation of MessageCache."""

    def __init__(self) -> None:
        self._messages: dict[str, list[Message]] = {}
        self._sync_rounds: dict[str, int] = {}

    async def store(self, messages: list[Message], participant: str) -> None:
        """Store messages for a conversation."""
        existing = self._messages.get(participant, [])
        existing_ids = {m.id for m in existing}

        for message in messages:
            if message.id not in existing_ids:
                existing.append(message)
                existing_ids.add(message.id)

        existing.sort(key=lambda m: m.timestamp)
        self._messages[participant] = existing

    async def retrieve(
        self,
        participant: str,
        after_round: Optional[int] = None,
    ) -> list[Message]:
        """Retrieve cached messages for a conversation."""
        messages = self._messages.get(participant, [])

        if after_round is not None:
            return [m for m in messages if m.confirmed_round > after_round]

        return list(messages)

    async def get_last_sync_round(self, participant: str) -> Optional[int]:
        """Get the last synced round for a conversation."""
        return self._sync_rounds.get(participant)

    async def set_last_sync_round(self, round: int, participant: str) -> None:
        """Set the last synced round for a conversation."""
        self._sync_rounds[participant] = round

    async def get_cached_conversations(self) -> list[str]:
        """Get all cached conversation participants."""
        return list(self._messages.keys())

    async def clear(self) -> None:
        """Clear all cached data."""
        self._messages.clear()
        self._sync_rounds.clear()

    async def clear_for(self, participant: str) -> None:
        """Clear cached data for a specific conversation."""
        self._messages.pop(participant, None)
        self._sync_rounds.pop(participant, None)
