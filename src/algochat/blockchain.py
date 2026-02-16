"""
Blockchain interfaces for Algorand integration.

This module provides abstract base classes for interacting with Algorand nodes (algod)
and indexers. Implementations can use any Algorand SDK.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

import base64

from .models import DiscoveredKey
from .signature import verify_encryption_key_bytes


def _decode_algorand_address(address: str) -> bytes:
    """Decodes an Algorand address to extract the 32-byte Ed25519 public key.

    Algorand addresses are base32-encoded: 32 bytes public key + 4 bytes checksum.

    Args:
        address: Algorand address string

    Returns:
        32-byte Ed25519 public key
    """
    decoded = base64.b32decode(address + "=" * ((8 - len(address) % 8) % 8))
    return decoded[:32]


@dataclass
class AlgorandConfig:
    """Configuration for Algorand node connections."""

    algod_url: str
    """Algod node URL."""

    algod_token: str
    """Algod API token."""

    indexer_url: Optional[str] = None
    """Indexer URL (optional)."""

    indexer_token: Optional[str] = None
    """Indexer API token (optional)."""

    @classmethod
    def localnet(cls) -> "AlgorandConfig":
        """Creates configuration for LocalNet (Algokit sandbox)."""
        return cls(
            algod_url="http://localhost:4001",
            algod_token="a" * 64,
            indexer_url="http://localhost:8980",
            indexer_token="a" * 64,
        )

    @classmethod
    def testnet(cls) -> "AlgorandConfig":
        """Creates configuration for TestNet (via Nodely)."""
        return cls(
            algod_url="https://testnet-api.4160.nodely.dev",
            algod_token="",
            indexer_url="https://testnet-idx.4160.nodely.dev",
            indexer_token="",
        )

    @classmethod
    def mainnet(cls) -> "AlgorandConfig":
        """Creates configuration for MainNet (via Nodely)."""
        return cls(
            algod_url="https://mainnet-api.4160.nodely.dev",
            algod_token="",
            indexer_url="https://mainnet-idx.4160.nodely.dev",
            indexer_token="",
        )

    def with_indexer(self, url: str, token: str) -> "AlgorandConfig":
        """Sets the indexer configuration."""
        return AlgorandConfig(
            algod_url=self.algod_url,
            algod_token=self.algod_token,
            indexer_url=url,
            indexer_token=token,
        )


@dataclass
class TransactionInfo:
    """Transaction information returned after submission."""

    txid: str
    """Transaction ID."""

    confirmed_round: Optional[int] = None
    """Round in which the transaction was confirmed (if confirmed)."""


@dataclass
class NoteTransaction:
    """A note field transaction from the blockchain."""

    txid: str
    """Transaction ID."""

    sender: str
    """Sender address."""

    receiver: str
    """Receiver address."""

    note: bytes
    """Note field contents."""

    confirmed_round: int
    """Round in which the transaction was confirmed."""

    round_time: int
    """Timestamp of the block (Unix time)."""


@dataclass
class SuggestedParams:
    """Suggested transaction parameters."""

    fee: int
    """Fee per byte in microAlgos."""

    min_fee: int
    """Minimum fee in microAlgos."""

    first_valid: int
    """First valid round."""

    last_valid: int
    """Last valid round."""

    genesis_id: str
    """Genesis ID."""

    genesis_hash: bytes
    """Genesis hash (32 bytes)."""


@dataclass
class AccountInfo:
    """Account information."""

    address: str
    """Account address."""

    amount: int
    """Account balance in microAlgos."""

    min_balance: int
    """Minimum balance required."""


class AlgodClient(ABC):
    """Abstract base class for interacting with an Algorand node (algod)."""

    @abstractmethod
    async def get_suggested_params(self) -> SuggestedParams:
        """Get the current network parameters."""
        pass

    @abstractmethod
    async def get_account_info(self, address: str) -> AccountInfo:
        """Get account information."""
        pass

    @abstractmethod
    async def submit_transaction(self, signed_txn: bytes) -> str:
        """Submit a signed transaction."""
        pass

    @abstractmethod
    async def wait_for_confirmation(self, txid: str, rounds: int) -> TransactionInfo:
        """Wait for a transaction to be confirmed."""
        pass

    @abstractmethod
    async def get_current_round(self) -> int:
        """Get the current round."""
        pass


class IndexerClient(ABC):
    """Abstract base class for interacting with an Algorand indexer."""

    @abstractmethod
    async def search_transactions(
        self,
        address: str,
        after_round: Optional[int] = None,
        limit: Optional[int] = None,
    ) -> list[NoteTransaction]:
        """Search for transactions with notes sent to/from an address."""
        pass

    @abstractmethod
    async def search_transactions_between(
        self,
        address1: str,
        address2: str,
        after_round: Optional[int] = None,
        limit: Optional[int] = None,
    ) -> list[NoteTransaction]:
        """Search for transactions between two addresses."""
        pass

    @abstractmethod
    async def get_transaction(self, txid: str) -> NoteTransaction:
        """Get a specific transaction by ID."""
        pass

    @abstractmethod
    async def wait_for_indexer(self, txid: str, timeout_secs: int) -> NoteTransaction:
        """Wait for a transaction to be indexed."""
        pass


async def discover_encryption_key(
    indexer: IndexerClient,
    address: str,
) -> Optional[DiscoveredKey]:
    """
    Discovers the encryption public key for an Algorand address.

    This searches the indexer for key announcement transactions from the address.
    The key is considered verified if it was signed by the address's Ed25519 key.
    """
    # Search for transactions from this address
    transactions = await indexer.search_transactions(address, limit=100)

    # Look for key announcements in the note field
    for tx in transactions:
        if tx.sender != address:
            continue

        # Check if this is a key announcement (self-transfer with note)
        if tx.receiver != address:
            continue

        # Try to parse as key announcement
        key = _parse_key_announcement(tx.note, address)
        if key is not None:
            return key

    return None


def _parse_key_announcement(note: bytes, address: str) -> Optional[DiscoveredKey]:
    """Parses a key announcement from a transaction note."""
    # Key announcement format:
    # - 32 bytes: X25519 public key
    # - 64 bytes (optional): Ed25519 signature

    if len(note) < 32:
        return None

    public_key = note[:32]

    is_verified = False
    if len(note) >= 96:
        # Has signature, verify it
        signature = note[32:96]
        try:
            # Decode the Algorand address to get the Ed25519 public key
            ed25519_public_key = _decode_algorand_address(address)
            is_verified = verify_encryption_key_bytes(public_key, ed25519_public_key, signature)
        except Exception:
            is_verified = False

    return DiscoveredKey(public_key=public_key, is_verified=is_verified)
