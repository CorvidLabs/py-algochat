"""Tests for the send queue."""

import pytest
from datetime import timedelta
from algochat.queue import SendQueue, QueueConfig
from algochat.models import PendingMessage, PendingStatus


# ============================================================================
# SendQueue
# ============================================================================


class TestSendQueue:
    @pytest.fixture
    def queue(self):
        return SendQueue()

    @pytest.fixture
    def small_queue(self):
        return SendQueue(config=QueueConfig(max_queue_size=3, max_retries=2))

    @pytest.mark.asyncio
    async def test_enqueue_and_next_pending(self, queue):
        pm = PendingMessage.create(recipient="BOB", content="hello")
        await queue.enqueue(pm)
        result = await queue.next_pending()
        assert result is not None
        assert result.content == "hello"

    @pytest.mark.asyncio
    async def test_next_pending_empty(self, queue):
        assert await queue.next_pending() is None

    @pytest.mark.asyncio
    async def test_all_pending(self, queue):
        pm1 = PendingMessage.create(recipient="BOB", content="hello")
        pm2 = PendingMessage.create(recipient="CAROL", content="world")
        await queue.enqueue(pm1)
        await queue.enqueue(pm2)
        pending = await queue.all_pending()
        assert len(pending) == 2

    @pytest.mark.asyncio
    async def test_mark_sending(self, queue):
        pm = PendingMessage.create(recipient="BOB", content="hello")
        await queue.enqueue(pm)
        await queue.mark_sending(pm.id)
        assert pm.status == PendingStatus.SENDING
        # Should no longer appear as pending
        assert await queue.next_pending() is None

    @pytest.mark.asyncio
    async def test_mark_sent(self, queue):
        pm = PendingMessage.create(recipient="BOB", content="hello")
        await queue.enqueue(pm)
        await queue.mark_sent(pm.id)
        assert pm.status == PendingStatus.SENT

    @pytest.mark.asyncio
    async def test_mark_failed(self, queue):
        pm = PendingMessage.create(recipient="BOB", content="hello")
        await queue.enqueue(pm)
        await queue.mark_failed(pm.id, "timeout")
        assert pm.status == PendingStatus.FAILED
        assert pm.last_error == "timeout"
        assert pm.retry_count == 1

    @pytest.mark.asyncio
    async def test_mark_sending_unknown_raises(self, queue):
        with pytest.raises(KeyError):
            await queue.mark_sending("nonexistent")

    @pytest.mark.asyncio
    async def test_mark_sent_unknown_raises(self, queue):
        with pytest.raises(KeyError):
            await queue.mark_sent("nonexistent")

    @pytest.mark.asyncio
    async def test_mark_failed_unknown_raises(self, queue):
        with pytest.raises(KeyError):
            await queue.mark_failed("nonexistent", "err")

    @pytest.mark.asyncio
    async def test_remove(self, queue):
        pm = PendingMessage.create(recipient="BOB", content="hello")
        await queue.enqueue(pm)
        removed = await queue.remove(pm.id)
        assert removed is not None
        assert removed.id == pm.id
        assert await queue.is_empty()

    @pytest.mark.asyncio
    async def test_remove_nonexistent(self, queue):
        result = await queue.remove("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_prune_sent(self, queue):
        pm1 = PendingMessage.create(recipient="BOB", content="hello")
        pm2 = PendingMessage.create(recipient="BOB", content="world")
        await queue.enqueue(pm1)
        await queue.enqueue(pm2)
        await queue.mark_sent(pm1.id)
        await queue.prune_sent()
        assert await queue.pending_count() == 1

    @pytest.mark.asyncio
    async def test_prune_failed(self, small_queue):
        pm = PendingMessage.create(recipient="BOB", content="hello")
        await small_queue.enqueue(pm)
        # Exceed max_retries (2)
        await small_queue.mark_failed(pm.id, "err")
        await small_queue.mark_failed(pm.id, "err")
        await small_queue.prune_failed()
        assert await small_queue.failed_count() == 0

    @pytest.mark.asyncio
    async def test_clear(self, queue):
        pm = PendingMessage.create(recipient="BOB", content="hello")
        await queue.enqueue(pm)
        await queue.clear()
        assert await queue.is_empty()

    @pytest.mark.asyncio
    async def test_is_empty(self, queue):
        assert await queue.is_empty()
        pm = PendingMessage.create(recipient="BOB", content="hello")
        await queue.enqueue(pm)
        assert not await queue.is_empty()

    @pytest.mark.asyncio
    async def test_pending_count(self, queue):
        assert await queue.pending_count() == 0
        pm = PendingMessage.create(recipient="BOB", content="hello")
        await queue.enqueue(pm)
        assert await queue.pending_count() == 1
        await queue.mark_sent(pm.id)
        assert await queue.pending_count() == 0

    @pytest.mark.asyncio
    async def test_failed_count(self, queue):
        pm = PendingMessage.create(recipient="BOB", content="hello")
        await queue.enqueue(pm)
        assert await queue.failed_count() == 0
        await queue.mark_failed(pm.id, "err")
        assert await queue.failed_count() == 1

    @pytest.mark.asyncio
    async def test_messages_for(self, queue):
        pm1 = PendingMessage.create(recipient="BOB", content="hello")
        pm2 = PendingMessage.create(recipient="CAROL", content="world")
        pm3 = PendingMessage.create(recipient="BOB", content="again")
        await queue.enqueue(pm1)
        await queue.enqueue(pm2)
        await queue.enqueue(pm3)
        bob_msgs = await queue.messages_for("BOB")
        assert len(bob_msgs) == 2

    @pytest.mark.asyncio
    async def test_queue_full_raises(self, small_queue):
        for i in range(3):
            await small_queue.enqueue(
                PendingMessage.create(recipient="BOB", content=f"msg-{i}")
            )
        with pytest.raises(RuntimeError, match="Queue is full"):
            await small_queue.enqueue(
                PendingMessage.create(recipient="BOB", content="overflow")
            )

    @pytest.mark.asyncio
    async def test_queue_full_evicts_dead_failed(self, small_queue):
        """When queue is full, non-retryable failed messages are evicted."""
        for i in range(3):
            pm = PendingMessage.create(recipient="BOB", content=f"msg-{i}")
            await small_queue.enqueue(pm)
            # Fail beyond max_retries (2)
            await small_queue.mark_failed(pm.id, "err")
            await small_queue.mark_failed(pm.id, "err")

        # Should succeed because dead-failed messages get evicted
        new_pm = PendingMessage.create(recipient="BOB", content="new")
        await small_queue.enqueue(new_pm)
        assert await small_queue.pending_count() == 1

    @pytest.mark.asyncio
    async def test_ready_for_retry(self):
        queue = SendQueue(
            config=QueueConfig(retry_delay=timedelta(seconds=0), max_retries=3)
        )
        pm = PendingMessage.create(recipient="BOB", content="hello")
        await queue.enqueue(pm)
        await queue.mark_failed(pm.id, "err")
        # With 0 delay, should be immediately ready
        retryable = await queue.ready_for_retry()
        assert len(retryable) == 1
        assert retryable[0].id == pm.id

    @pytest.mark.asyncio
    async def test_ready_for_retry_respects_delay(self):
        queue = SendQueue(
            config=QueueConfig(retry_delay=timedelta(hours=1), max_retries=3)
        )
        pm = PendingMessage.create(recipient="BOB", content="hello")
        await queue.enqueue(pm)
        await queue.mark_sending(pm.id)  # Sets last_attempt
        await queue.mark_failed(pm.id, "err")
        retryable = await queue.ready_for_retry()
        assert len(retryable) == 0  # Not enough time passed since last_attempt

    @pytest.mark.asyncio
    async def test_reset_for_retry(self, queue):
        pm = PendingMessage.create(recipient="BOB", content="hello")
        await queue.enqueue(pm)
        await queue.mark_failed(pm.id, "err")
        await queue.reset_for_retry(pm.id)
        assert pm.status == PendingStatus.PENDING

    @pytest.mark.asyncio
    async def test_reset_for_retry_exceeded_raises(self, small_queue):
        pm = PendingMessage.create(recipient="BOB", content="hello")
        await small_queue.enqueue(pm)
        await small_queue.mark_failed(pm.id, "err")
        await small_queue.mark_failed(pm.id, "err")
        with pytest.raises(RuntimeError, match="exceeded max retries"):
            await small_queue.reset_for_retry(pm.id)

    @pytest.mark.asyncio
    async def test_reset_for_retry_unknown_raises(self, queue):
        with pytest.raises(KeyError):
            await queue.reset_for_retry("nonexistent")

    @pytest.mark.asyncio
    async def test_config_defaults(self):
        queue = SendQueue()
        assert queue.config.max_retries == 3
        assert queue.config.max_queue_size == 100
        assert queue.config.retry_delay == timedelta(seconds=5)
