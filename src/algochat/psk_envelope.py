"""PSK envelope encoding and decoding for the v1.1 protocol."""

from .psk_types import (
    PSK_VERSION,
    PSK_PROTOCOL_ID,
    PSK_HEADER_SIZE,
    PSK_ENCRYPTED_SENDER_KEY_SIZE,
    PSKEnvelope,
)
from .types import PUBLIC_KEY_SIZE, NONCE_SIZE


class PSKEnvelopeError(Exception):
    """Raised when PSK envelope encoding/decoding fails."""
    pass


def encode_psk_envelope(envelope: PSKEnvelope) -> bytes:
    """Encode a PSK envelope to bytes.

    Format (130-byte header + ciphertext):
        [0]       version (0x01)
        [1]       protocolId (0x02)
        [2..5]    ratchetCounter (4 bytes, big-endian uint32)
        [6..37]   senderPublicKey (32 bytes)
        [38..69]  ephemeralPublicKey (32 bytes)
        [70..81]  nonce (12 bytes)
        [82..129] encryptedSenderKey (48 bytes)
        [130..]   ciphertext (variable)

    Args:
        envelope: PSKEnvelope to encode.

    Returns:
        Encoded bytes.
    """
    return (
        bytes([PSK_VERSION, PSK_PROTOCOL_ID])
        + envelope.ratchet_counter.to_bytes(4, byteorder="big")
        + envelope.sender_public_key
        + envelope.ephemeral_public_key
        + envelope.nonce
        + envelope.encrypted_sender_key
        + envelope.ciphertext
    )


def decode_psk_envelope(data: bytes) -> PSKEnvelope:
    """Decode bytes into a PSK envelope.

    Args:
        data: Encoded envelope bytes.

    Returns:
        Decoded PSKEnvelope.

    Raises:
        PSKEnvelopeError: If data is invalid.
    """
    if len(data) < PSK_HEADER_SIZE:
        raise PSKEnvelopeError(
            f"Data too short: {len(data)} bytes (minimum {PSK_HEADER_SIZE})"
        )

    version = data[0]
    protocol_id = data[1]

    if version != PSK_VERSION:
        raise PSKEnvelopeError(f"Unknown version: {version}")

    if protocol_id != PSK_PROTOCOL_ID:
        raise PSKEnvelopeError(f"Unknown protocol ID: {protocol_id}")

    offset = 2
    ratchet_counter = int.from_bytes(data[offset : offset + 4], byteorder="big")
    offset += 4

    sender_public_key = data[offset : offset + PUBLIC_KEY_SIZE]
    offset += PUBLIC_KEY_SIZE

    ephemeral_public_key = data[offset : offset + PUBLIC_KEY_SIZE]
    offset += PUBLIC_KEY_SIZE

    nonce = data[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE

    encrypted_sender_key = data[offset : offset + PSK_ENCRYPTED_SENDER_KEY_SIZE]
    offset += PSK_ENCRYPTED_SENDER_KEY_SIZE

    ciphertext = data[offset:]

    return PSKEnvelope(
        ratchet_counter=ratchet_counter,
        sender_public_key=sender_public_key,
        ephemeral_public_key=ephemeral_public_key,
        nonce=nonce,
        encrypted_sender_key=encrypted_sender_key,
        ciphertext=ciphertext,
    )


def is_psk_message(data: bytes) -> bool:
    """Check if data looks like a valid PSK envelope.

    Args:
        data: Bytes to check.

    Returns:
        True if data appears to be a valid PSK envelope.
    """
    if len(data) < PSK_HEADER_SIZE:
        return False

    return data[0] == PSK_VERSION and data[1] == PSK_PROTOCOL_ID
