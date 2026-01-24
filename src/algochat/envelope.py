"""Envelope encoding and decoding for AlgoChat protocol."""

from dataclasses import dataclass

from .types import (
    PROTOCOL_VERSION,
    PROTOCOL_ID,
    HEADER_SIZE,
    PUBLIC_KEY_SIZE,
    NONCE_SIZE,
    ENCRYPTED_SENDER_KEY_SIZE,
)


@dataclass
class ChatEnvelope:
    """AlgoChat message envelope."""
    version: int
    protocol_id: int
    sender_public_key: bytes  # 32 bytes
    ephemeral_public_key: bytes  # 32 bytes
    nonce: bytes  # 12 bytes
    encrypted_sender_key: bytes  # 48 bytes (32 + 16 tag)
    ciphertext: bytes  # variable (message + 16-byte tag)


class EnvelopeError(Exception):
    """Raised when envelope encoding/decoding fails."""
    pass


def encode_envelope(envelope: ChatEnvelope) -> bytes:
    """
    Encode an envelope to bytes.

    Format (126-byte header + ciphertext):
        [0]      version (0x01)
        [1]      protocolId (0x01)
        [2-33]   senderPublicKey (32 bytes)
        [34-65]  ephemeralPublicKey (32 bytes)
        [66-77]  nonce (12 bytes)
        [78-125] encryptedSenderKey (48 bytes)
        [126+]   ciphertext (variable)

    Args:
        envelope: ChatEnvelope to encode

    Returns:
        Encoded bytes
    """
    return (
        bytes([envelope.version, envelope.protocol_id])
        + envelope.sender_public_key
        + envelope.ephemeral_public_key
        + envelope.nonce
        + envelope.encrypted_sender_key
        + envelope.ciphertext
    )


def decode_envelope(data: bytes) -> ChatEnvelope:
    """
    Decode bytes into an envelope.

    Args:
        data: Encoded envelope bytes

    Returns:
        Decoded ChatEnvelope

    Raises:
        EnvelopeError: If data is invalid
    """
    if len(data) < HEADER_SIZE:
        raise EnvelopeError(f"Data too short: {len(data)} bytes (minimum {HEADER_SIZE})")

    version = data[0]
    protocol_id = data[1]

    if version != PROTOCOL_VERSION:
        raise EnvelopeError(f"Unknown version: {version}")

    if protocol_id != PROTOCOL_ID:
        raise EnvelopeError(f"Unknown protocol ID: {protocol_id}")

    offset = 2
    sender_public_key = data[offset : offset + PUBLIC_KEY_SIZE]
    offset += PUBLIC_KEY_SIZE

    ephemeral_public_key = data[offset : offset + PUBLIC_KEY_SIZE]
    offset += PUBLIC_KEY_SIZE

    nonce = data[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE

    encrypted_sender_key = data[offset : offset + ENCRYPTED_SENDER_KEY_SIZE]
    offset += ENCRYPTED_SENDER_KEY_SIZE

    ciphertext = data[offset:]

    return ChatEnvelope(
        version=version,
        protocol_id=protocol_id,
        sender_public_key=sender_public_key,
        ephemeral_public_key=ephemeral_public_key,
        nonce=nonce,
        encrypted_sender_key=encrypted_sender_key,
        ciphertext=ciphertext,
    )


def is_chat_message(data: bytes) -> bool:
    """
    Check if data looks like a valid AlgoChat envelope.

    Args:
        data: Bytes to check

    Returns:
        True if data appears to be a valid envelope
    """
    if len(data) < HEADER_SIZE:
        return False

    return data[0] == PROTOCOL_VERSION and data[1] == PROTOCOL_ID
