"""PSK counter state management for replay protection."""

from dataclasses import dataclass, field

from .psk_types import PSK_COUNTER_WINDOW


@dataclass
class PSKState:
    """Tracks send/receive counter state for a PSK conversation.

    Attributes:
        send_counter: The next counter to use when sending.
        peer_last_counter: The highest counter received from the peer.
        seen_counters: Set of recently seen counters for replay protection.
    """

    send_counter: int = 0
    peer_last_counter: int = -1
    seen_counters: set = field(default_factory=set)


def validate_counter(state: PSKState, counter: int) -> bool:
    """Validate an incoming ratchet counter against the current state.

    Rejects counters that are:
        - Negative
        - Already seen (replay protection)
        - Too far behind the latest counter (outside the window)

    Args:
        state: The current PSK state.
        counter: The incoming ratchet counter.

    Returns:
        True if the counter is valid.
    """
    if counter < 0:
        return False

    if counter in state.seen_counters:
        return False

    # Allow counters within the window or any future counter
    if state.peer_last_counter >= 0:
        lower_bound = max(0, state.peer_last_counter - PSK_COUNTER_WINDOW)
        if counter < lower_bound:
            return False

    return True


def record_receive(state: PSKState, counter: int) -> PSKState:
    """Record a received counter and return updated state.

    Args:
        state: The current PSK state.
        counter: The received ratchet counter.

    Returns:
        Updated PSKState with the counter recorded.
    """
    new_seen = set(state.seen_counters)
    new_seen.add(counter)

    new_peer_last = max(state.peer_last_counter, counter)

    # Prune counters outside the window
    if new_peer_last >= 0:
        lower_bound = max(0, new_peer_last - PSK_COUNTER_WINDOW)
        new_seen = {c for c in new_seen if c >= lower_bound}

    return PSKState(
        send_counter=state.send_counter,
        peer_last_counter=new_peer_last,
        seen_counters=new_seen,
    )


def advance_send_counter(state: PSKState) -> tuple:
    """Advance the send counter and return the counter to use.

    Args:
        state: The current PSK state.

    Returns:
        Tuple of (counter_to_use, updated_state).
    """
    counter = state.send_counter
    new_state = PSKState(
        send_counter=state.send_counter + 1,
        peer_last_counter=state.peer_last_counter,
        seen_counters=set(state.seen_counters),
    )
    return counter, new_state
