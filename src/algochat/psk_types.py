"""Type definitions for the PSK (Pre-Shared Key) v1.1 protocol."""

from dataclasses import dataclass


# Protocol constants
PSK_VERSION = 0x01
PSK_PROTOCOL_ID = 0x02
PSK_HEADER_SIZE = 130
PSK_TAG_SIZE = 16
PSK_ENCRYPTED_SENDER_KEY_SIZE = 48  # 32-byte key + 16-byte tag
PSK_MAX_PAYLOAD_SIZE = 878
PSK_SESSION_SIZE = 100
PSK_COUNTER_WINDOW = 200


@dataclass
class PSKEnvelope:
    """PSK protocol message envelope.

    Wire format (130-byte header + variable ciphertext):
        [0]       version (0x01)
        [1]       protocolId (0x02)
        [2..5]    ratchetCounter (4 bytes, big-endian uint32)
        [6..37]   senderPublicKey (32 bytes)
        [38..69]  ephemeralPublicKey (32 bytes)
        [70..81]  nonce (12 bytes)
        [82..129] encryptedSenderKey (48 bytes)
        [130..]   ciphertext + 16-byte tag
    """

    ratchet_counter: int
    sender_public_key: bytes  # 32 bytes
    ephemeral_public_key: bytes  # 32 bytes
    nonce: bytes  # 12 bytes
    encrypted_sender_key: bytes  # 48 bytes (32 + 16 tag)
    ciphertext: bytes  # variable (message + 16-byte tag)
