"""Tests for data models."""

from datetime import datetime
from algochat.models import (
    ReplyContext,
    Message,
    MessageDirection,
    Conversation,
    DiscoveredKey,
    SendOptions,
    PendingMessage,
    PendingStatus,
)


# ============================================================================
# Fixtures
# ============================================================================


def make_message(
    id: str = "txid-1",
    sender: str = "ALICE",
    recipient: str = "BOB",
    content: str = "hello",
    direction: MessageDirection = MessageDirection.SENT,
    confirmed_round: int = 100,
    timestamp: datetime | None = None,
    reply_context: ReplyContext | None = None,
) -> Message:
    return Message(
        id=id,
        sender=sender,
        recipient=recipient,
        content=content,
        timestamp=timestamp or datetime(2026, 3, 5, 12, 0, 0),
        confirmed_round=confirmed_round,
        direction=direction,
        reply_context=reply_context,
    )


# ============================================================================
# ReplyContext
# ============================================================================


class TestReplyContext:
    def test_from_message_short_content(self):
        msg = make_message(content="short")
        ctx = ReplyContext.from_message(msg)
        assert ctx.message_id == "txid-1"
        assert ctx.preview == "short"

    def test_from_message_truncates_long_content(self):
        long = "a" * 100
        msg = make_message(content=long)
        ctx = ReplyContext.from_message(msg)
        assert len(ctx.preview) == 80
        assert ctx.preview.endswith("...")

    def test_from_message_exact_boundary(self):
        msg = make_message(content="a" * 80)
        ctx = ReplyContext.from_message(msg)
        assert ctx.preview == "a" * 80  # exactly at max_length, no truncation

    def test_from_message_custom_max_length(self):
        msg = make_message(content="a" * 50)
        ctx = ReplyContext.from_message(msg, max_length=20)
        assert len(ctx.preview) == 20
        assert ctx.preview.endswith("...")

    def test_from_message_empty_content(self):
        msg = make_message(content="")
        ctx = ReplyContext.from_message(msg)
        assert ctx.preview == ""


# ============================================================================
# Message
# ============================================================================


class TestMessage:
    def test_basic_properties(self):
        msg = make_message()
        assert msg.id == "txid-1"
        assert msg.sender == "ALICE"
        assert msg.recipient == "BOB"
        assert msg.content == "hello"
        assert msg.direction == MessageDirection.SENT
        assert msg.confirmed_round == 100

    def test_is_reply_false_by_default(self):
        msg = make_message()
        assert msg.is_reply is False

    def test_is_reply_true_with_context(self):
        ctx = ReplyContext(message_id="txid-0", preview="original")
        msg = make_message(reply_context=ctx)
        assert msg.is_reply is True
        assert msg.reply_context.preview == "original"

    def test_hash_by_id(self):
        m1 = make_message(id="txid-1", content="aaa")
        m2 = make_message(id="txid-1", content="bbb")
        assert hash(m1) == hash(m2)

    def test_equality_by_id(self):
        m1 = make_message(id="txid-1", content="aaa")
        m2 = make_message(id="txid-1", content="bbb")
        assert m1 == m2

    def test_inequality_different_id(self):
        m1 = make_message(id="txid-1")
        m2 = make_message(id="txid-2")
        assert m1 != m2

    def test_equality_not_implemented_for_other_types(self):
        msg = make_message()
        assert msg.__eq__("not a message") is NotImplemented

    def test_message_in_set(self):
        m1 = make_message(id="txid-1")
        m2 = make_message(id="txid-1")
        m3 = make_message(id="txid-2")
        s = {m1, m2, m3}
        assert len(s) == 2

    def test_direction_enum_values(self):
        assert MessageDirection.SENT.value == "sent"
        assert MessageDirection.RECEIVED.value == "received"


# ============================================================================
# Conversation
# ============================================================================


class TestConversation:
    def test_empty_conversation(self):
        conv = Conversation(participant="ALICE")
        assert conv.id == "ALICE"
        assert conv.is_empty is True
        assert conv.message_count == 0
        assert conv.last_message is None
        assert conv.last_received is None
        assert conv.last_sent is None
        assert conv.messages == []

    def test_append_message(self):
        conv = Conversation(participant="ALICE")
        msg = make_message()
        conv.append(msg)
        assert conv.message_count == 1
        assert conv.is_empty is False
        assert conv.last_message == msg

    def test_append_deduplicates(self):
        conv = Conversation(participant="ALICE")
        msg = make_message(id="txid-1")
        conv.append(msg)
        conv.append(msg)
        assert conv.message_count == 1

    def test_append_sorts_chronologically(self):
        conv = Conversation(participant="ALICE")
        m1 = make_message(id="txid-1", timestamp=datetime(2026, 3, 5, 12, 0, 0))
        m2 = make_message(id="txid-2", timestamp=datetime(2026, 3, 5, 11, 0, 0))
        conv.append(m1)
        conv.append(m2)
        assert conv.messages[0].id == "txid-2"  # earlier first
        assert conv.messages[1].id == "txid-1"

    def test_merge_messages(self):
        conv = Conversation(participant="ALICE")
        msgs = [
            make_message(id="txid-1", timestamp=datetime(2026, 3, 5, 12, 0, 0)),
            make_message(id="txid-2", timestamp=datetime(2026, 3, 5, 13, 0, 0)),
        ]
        conv.merge(msgs)
        assert conv.message_count == 2

    def test_merge_deduplicates(self):
        conv = Conversation(participant="ALICE")
        m1 = make_message(id="txid-1")
        conv.append(m1)
        conv.merge([m1, make_message(id="txid-2")])
        assert conv.message_count == 2

    def test_last_received(self):
        conv = Conversation(participant="ALICE")
        conv.append(make_message(id="txid-1", direction=MessageDirection.SENT))
        conv.append(
            make_message(
                id="txid-2",
                direction=MessageDirection.RECEIVED,
                timestamp=datetime(2026, 3, 5, 13, 0, 0),
            )
        )
        assert conv.last_received.id == "txid-2"

    def test_last_sent(self):
        conv = Conversation(participant="ALICE")
        conv.append(
            make_message(
                id="txid-1",
                direction=MessageDirection.RECEIVED,
                timestamp=datetime(2026, 3, 5, 11, 0, 0),
            )
        )
        conv.append(
            make_message(
                id="txid-2",
                direction=MessageDirection.SENT,
                timestamp=datetime(2026, 3, 5, 12, 0, 0),
            )
        )
        assert conv.last_sent.id == "txid-2"

    def test_received_messages_iterator(self):
        conv = Conversation(participant="ALICE")
        conv.append(make_message(id="txid-1", direction=MessageDirection.SENT))
        conv.append(
            make_message(
                id="txid-2",
                direction=MessageDirection.RECEIVED,
                timestamp=datetime(2026, 3, 5, 13, 0, 0),
            )
        )
        received = list(conv.received_messages)
        assert len(received) == 1
        assert received[0].id == "txid-2"

    def test_sent_messages_iterator(self):
        conv = Conversation(participant="ALICE")
        conv.append(make_message(id="txid-1", direction=MessageDirection.SENT))
        conv.append(
            make_message(
                id="txid-2",
                direction=MessageDirection.RECEIVED,
                timestamp=datetime(2026, 3, 5, 13, 0, 0),
            )
        )
        sent = list(conv.sent_messages)
        assert len(sent) == 1
        assert sent[0].id == "txid-1"

    def test_participant_encryption_key(self):
        conv = Conversation(participant="ALICE", participant_encryption_key=b"\x01" * 32)
        assert conv.participant_encryption_key == b"\x01" * 32

    def test_last_fetched_round(self):
        conv = Conversation(participant="ALICE")
        assert conv.last_fetched_round is None
        conv.last_fetched_round = 500
        assert conv.last_fetched_round == 500


# ============================================================================
# DiscoveredKey
# ============================================================================


class TestDiscoveredKey:
    def test_verified_key(self):
        dk = DiscoveredKey(public_key=b"\x02" * 32, is_verified=True)
        assert dk.is_verified is True
        assert len(dk.public_key) == 32

    def test_unverified_key(self):
        dk = DiscoveredKey(public_key=b"\x03" * 32, is_verified=False)
        assert dk.is_verified is False


# ============================================================================
# SendOptions
# ============================================================================


class TestSendOptions:
    def test_fire_and_forget(self):
        opts = SendOptions.fire_and_forget()
        assert opts.wait_for_confirmation is False
        assert opts.wait_for_indexer is False

    def test_confirmed(self):
        opts = SendOptions.confirmed()
        assert opts.wait_for_confirmation is True
        assert opts.wait_for_indexer is False

    def test_indexed(self):
        opts = SendOptions.indexed()
        assert opts.wait_for_confirmation is True
        assert opts.wait_for_indexer is True

    def test_replying_to(self):
        msg = make_message(content="original message")
        opts = SendOptions.replying_to(msg)
        assert opts.reply_context is not None
        assert opts.reply_context.message_id == "txid-1"
        assert opts.reply_context.preview == "original message"

    def test_default_timeouts(self):
        opts = SendOptions()
        assert opts.timeout_rounds == 10
        assert opts.indexer_timeout_secs == 30


# ============================================================================
# PendingMessage
# ============================================================================


class TestPendingMessage:
    def test_create(self):
        pm = PendingMessage.create(recipient="BOB", content="hello")
        assert pm.recipient == "BOB"
        assert pm.content == "hello"
        assert pm.status == PendingStatus.PENDING
        assert pm.retry_count == 0
        assert pm.last_error is None
        assert pm.last_attempt is None
        assert pm.id  # UUID was generated

    def test_create_with_reply(self):
        ctx = ReplyContext(message_id="txid-0", preview="original")
        pm = PendingMessage.create(recipient="BOB", content="reply", reply_context=ctx)
        assert pm.reply_context is not None
        assert pm.reply_context.message_id == "txid-0"

    def test_mark_sending(self):
        pm = PendingMessage.create(recipient="BOB", content="hello")
        pm.mark_sending()
        assert pm.status == PendingStatus.SENDING
        assert pm.last_attempt is not None

    def test_mark_sent(self):
        pm = PendingMessage.create(recipient="BOB", content="hello")
        pm.mark_sent()
        assert pm.status == PendingStatus.SENT

    def test_mark_failed(self):
        pm = PendingMessage.create(recipient="BOB", content="hello")
        pm.mark_failed("network error")
        assert pm.status == PendingStatus.FAILED
        assert pm.retry_count == 1
        assert pm.last_error == "network error"

    def test_can_retry_within_limit(self):
        pm = PendingMessage.create(recipient="BOB", content="hello")
        pm.mark_failed("err")
        assert pm.can_retry(max_retries=3) is True

    def test_cannot_retry_at_limit(self):
        pm = PendingMessage.create(recipient="BOB", content="hello")
        pm.mark_failed("err")
        pm.mark_failed("err")
        pm.mark_failed("err")
        assert pm.can_retry(max_retries=3) is False

    def test_cannot_retry_if_not_failed(self):
        pm = PendingMessage.create(recipient="BOB", content="hello")
        assert pm.can_retry(max_retries=3) is False  # still PENDING

    def test_pending_status_enum_values(self):
        assert PendingStatus.PENDING.value == "pending"
        assert PendingStatus.SENDING.value == "sending"
        assert PendingStatus.FAILED.value == "failed"
        assert PendingStatus.SENT.value == "sent"

    def test_unique_ids(self):
        pm1 = PendingMessage.create(recipient="BOB", content="hello")
        pm2 = PendingMessage.create(recipient="BOB", content="hello")
        assert pm1.id != pm2.id
