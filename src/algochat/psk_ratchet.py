"""PSK ratchet key derivation for the v1.1 protocol.

Two-level ratchet:
    - Session PSK: derived per session (every PSK_SESSION_SIZE messages)
    - Position PSK: derived per position within a session
"""

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

from .psk_types import PSK_SESSION_SIZE


def derive_session_psk(initial_psk: bytes, session_index: int) -> bytes:
    """Derive a session PSK from the initial PSK and session index.

    Args:
        initial_psk: The initial pre-shared key (32 bytes).
        session_index: The session index (0-based).

    Returns:
        32-byte session PSK.
    """
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=b"AlgoChat-PSK-Session",
        info=session_index.to_bytes(4, byteorder="big"),
    )
    return hkdf.derive(initial_psk)


def derive_position_psk(session_psk: bytes, position: int) -> bytes:
    """Derive a position PSK from a session PSK and position.

    Args:
        session_psk: The session PSK (32 bytes).
        position: The position within the session (0-based).

    Returns:
        32-byte position PSK.
    """
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=b"AlgoChat-PSK-Position",
        info=position.to_bytes(4, byteorder="big"),
    )
    return hkdf.derive(session_psk)


def derive_psk_at_counter(initial_psk: bytes, counter: int) -> bytes:
    """Derive the PSK for a given ratchet counter.

    The counter is split into session_index and position:
        session_index = counter // PSK_SESSION_SIZE
        position = counter % PSK_SESSION_SIZE

    Args:
        initial_psk: The initial pre-shared key (32 bytes).
        counter: The ratchet counter.

    Returns:
        32-byte derived PSK for this counter.
    """
    session_index = counter // PSK_SESSION_SIZE
    position = counter % PSK_SESSION_SIZE

    session_psk = derive_session_psk(initial_psk, session_index)
    return derive_position_psk(session_psk, position)


def derive_hybrid_symmetric_key(
    shared_secret: bytes,
    current_psk: bytes,
    ephemeral_public_key: bytes,
    sender_public_key: bytes,
    recipient_public_key: bytes,
) -> bytes:
    """Derive the hybrid symmetric key combining ECDH and PSK.

    Args:
        shared_secret: The X25519 ECDH shared secret (32 bytes).
        current_psk: The current ratcheted PSK (32 bytes).
        ephemeral_public_key: The ephemeral public key (32 bytes).
        sender_public_key: The sender's public key (32 bytes).
        recipient_public_key: The recipient's public key (32 bytes).

    Returns:
        32-byte symmetric key.
    """
    ikm = shared_secret + current_psk
    info = b"AlgoChatV1-PSK" + sender_public_key + recipient_public_key

    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=ephemeral_public_key,
        info=info,
    )
    return hkdf.derive(ikm)


def derive_sender_key(
    sender_shared_secret: bytes,
    current_psk: bytes,
    ephemeral_public_key: bytes,
    sender_public_key: bytes,
) -> bytes:
    """Derive the sender key for bidirectional decryption.

    Args:
        sender_shared_secret: The X25519 ECDH shared secret with sender (32 bytes).
        current_psk: The current ratcheted PSK (32 bytes).
        ephemeral_public_key: The ephemeral public key (32 bytes).
        sender_public_key: The sender's public key (32 bytes).

    Returns:
        32-byte sender encryption key.
    """
    ikm = sender_shared_secret + current_psk
    info = b"AlgoChatV1-PSK-SenderKey" + sender_public_key

    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=ephemeral_public_key,
        info=info,
    )
    return hkdf.derive(ikm)
