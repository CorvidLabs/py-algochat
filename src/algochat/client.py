"""
AlgoChat client for encrypted messaging on Algorand.

The AlgoChatClient provides a high-level API for sending and receiving
encrypted messages on the Algorand blockchain.
"""

from datetime import datetime
from typing import Optional, List

from .account import ChatAccount
from .blockchain import AlgodClient, IndexerClient, NoteTransaction
from .crypto import encrypt_message, decrypt_message
from .envelope import encode_envelope, decode_envelope, is_chat_message
from .models import (
    Message,
    MessageDirection,
    Conversation,
    DiscoveredKey,
    SendOptions,
    SendResult,
    ReplyContext,
)
from .storage import MessageCache, PublicKeyCache


class AlgoChatError(Exception):
    """Base exception for AlgoChat errors."""

    pass


class PublicKeyNotFoundError(AlgoChatError):
    """Raised when a user's public key cannot be found."""

    def __init__(self, address: str) -> None:
        self.address = address
        super().__init__(f"Public key not found for address: {address}")


class InsufficientBalanceError(AlgoChatError):
    """Raised when account has insufficient balance."""

    def __init__(self, required: int, available: int) -> None:
        self.required = required
        self.available = available
        super().__init__(
            f"Insufficient balance: required {required} microAlgos, available {available}"
        )


class MessageTooLargeError(AlgoChatError):
    """Raised when message exceeds maximum size."""

    def __init__(self, max_size: int) -> None:
        self.max_size = max_size
        super().__init__(f"Message exceeds maximum size of {max_size} bytes")


class AlgoChatClient:
    """
    High-level client for AlgoChat encrypted messaging.

    The AlgoChatClient provides methods for:
    - Sending encrypted messages
    - Fetching and decrypting messages
    - Managing conversations
    - Discovering encryption keys
    - Publishing your encryption key

    Example usage:
        ```python
        # Create client
        client = AlgoChatClient(
            account=chat_account,
            algod=my_algod_client,
            indexer=my_indexer_client,
        )

        # Send a message
        result = await client.send_message(
            "Hello, Algorand!",
            to="RECIPIENT_ADDRESS..."
        )

        # Fetch messages
        conv = await client.refresh_conversation("RECIPIENT_ADDRESS...")
        for msg in conv.messages:
            print(f"{msg.sender}: {msg.content}")
        ```
    """

    # Minimum transaction fee in microAlgos
    MIN_TRANSACTION_FEE = 1000

    # Minimum account balance in microAlgos
    MIN_ACCOUNT_BALANCE = 100_000

    # Maximum message payload size
    MAX_PAYLOAD_SIZE = 882

    def __init__(
        self,
        account: ChatAccount,
        algod: AlgodClient,
        indexer: IndexerClient,
        message_cache: Optional[MessageCache] = None,
        public_key_cache: Optional[PublicKeyCache] = None,
    ) -> None:
        """
        Initialize the AlgoChat client.

        Args:
            account: The ChatAccount to use for messaging.
            algod: AlgodClient for submitting transactions.
            indexer: IndexerClient for querying messages.
            message_cache: Optional cache for offline message access.
            public_key_cache: Optional cache for public keys (default: in-memory with 24h TTL).
        """
        self.account = account
        self.algod = algod
        self.indexer = indexer
        self.message_cache = message_cache
        self.public_key_cache = public_key_cache or PublicKeyCache()

    @property
    def address(self) -> str:
        """The account's Algorand address."""
        return self.account.address

    @property
    def public_key(self) -> bytes:
        """The account's encryption public key (32 bytes)."""
        return self.account.public_key_bytes

    # MARK: - Conversations

    async def conversation(self, participant: str) -> Conversation:
        """
        Get or create a conversation with a participant.

        Args:
            participant: The other party's Algorand address.

        Returns:
            A Conversation object (may be empty if no history exists).
        """
        conv = Conversation(participant=participant)

        # Try to get the participant's encryption key
        if participant == self.account.address:
            conv.participant_encryption_key = self.account.public_key_bytes
        else:
            try:
                discovered = await self.discover_key(participant)
                conv.participant_encryption_key = discovered.public_key
            except PublicKeyNotFoundError:
                pass

        return conv

    async def conversations(self, limit: int = 100) -> List[Conversation]:
        """
        Fetch all conversations for the current account.

        Args:
            limit: Maximum number of transactions to scan.

        Returns:
            List of conversations, sorted by most recent message.
        """
        transactions = await self.indexer.search_transactions(
            self.account.address, limit=limit
        )

        # Group by participant
        participants: dict[str, List[NoteTransaction]] = {}
        for tx in transactions:
            if not tx.note or not is_chat_message(tx.note):
                continue

            # Determine participant
            if tx.sender == self.account.address:
                participant = tx.receiver
            else:
                participant = tx.sender

            # Skip self-payments (key publishes)
            if participant == self.account.address:
                continue

            if participant not in participants:
                participants[participant] = []
            participants[participant].append(tx)

        # Build conversations
        convs: List[Conversation] = []
        for participant, txs in participants.items():
            conv = Conversation(participant=participant)
            messages = self._parse_messages(txs)
            conv.merge(messages)
            if not conv.is_empty():
                convs.append(conv)

        # Sort by most recent message
        convs.sort(
            key=lambda c: c.last_message().timestamp if c.last_message() else datetime.min,
            reverse=True,
        )

        return convs

    async def refresh_conversation(
        self,
        participant: str,
        after_round: Optional[int] = None,
        limit: int = 50,
    ) -> Conversation:
        """
        Fetch messages for a conversation.

        Args:
            participant: The conversation participant's address.
            after_round: Only fetch messages after this round (for incremental sync).
            limit: Maximum number of messages to fetch.

        Returns:
            Updated Conversation with messages.
        """
        conv = await self.conversation(participant)

        # Check cache for last sync round
        if after_round is None and self.message_cache:
            after_round = await self.message_cache.get_last_sync_round(participant)

        # Fetch transactions between accounts
        transactions = await self.indexer.search_transactions_between(
            self.account.address,
            participant,
            after_round=after_round,
            limit=limit,
        )

        # Parse and decrypt messages
        messages = self._parse_messages(transactions)
        conv.merge(messages)

        # Update last fetched round
        if messages:
            last_round = max(m.confirmed_round for m in messages)
            conv.last_fetched_round = last_round

            # Update cache
            if self.message_cache:
                await self.message_cache.store(messages, participant)
                await self.message_cache.set_last_sync_round(last_round, participant)

        # Try to discover participant's public key from received messages
        if conv.participant_encryption_key is None:
            if any(m.direction == MessageDirection.RECEIVED for m in messages):
                try:
                    discovered = await self.discover_key(participant)
                    conv.participant_encryption_key = discovered.public_key
                except PublicKeyNotFoundError:
                    pass

        return conv

    async def load_cached(self, participant: str) -> List[Message]:
        """
        Load cached messages for a conversation (offline access).

        Args:
            participant: The conversation participant.

        Returns:
            Cached messages, or empty list if no cache.
        """
        if not self.message_cache:
            return []

        try:
            return await self.message_cache.retrieve(participant)
        except Exception:
            return []

    # MARK: - Sending Messages

    async def send_message(
        self,
        content: str,
        to: str,
        options: Optional[SendOptions] = None,
    ) -> SendResult:
        """
        Send an encrypted message.

        Args:
            content: The message text.
            to: Recipient's Algorand address.
            options: Send options (default: fire-and-forget).

        Returns:
            SendResult with transaction ID and message.

        Raises:
            MessageTooLargeError: If message exceeds max size.
            InsufficientBalanceError: If account balance is too low.
            PublicKeyNotFoundError: If recipient's key cannot be found.
        """
        options = options or SendOptions.fire_and_forget()

        # Validate message size
        message_bytes = content.encode("utf-8")
        if len(message_bytes) > self.MAX_PAYLOAD_SIZE:
            raise MessageTooLargeError(self.MAX_PAYLOAD_SIZE)

        # Check balance
        account_info = await self.algod.get_account_info(self.account.address)
        required = self.MIN_TRANSACTION_FEE + self.MIN_ACCOUNT_BALANCE
        if account_info.amount < required:
            raise InsufficientBalanceError(required, account_info.amount)

        # Get recipient's public key
        recipient_key = await self._get_recipient_key(to)

        # Encrypt message
        from .keys import public_key_from_bytes

        recipient_public_key = public_key_from_bytes(recipient_key)

        envelope = encrypt_message(
            content,
            self.account.encryption_private_key,
            self.account.encryption_public_key,
            recipient_public_key,
            reply_to=options.reply_context,
        )

        # Encode envelope
        note = encode_envelope(envelope)

        # Get transaction parameters
        params = await self.algod.get_suggested_params()

        # Build and sign transaction
        # Note: This requires the caller to have implemented transaction building
        # in their AlgodClient. We'll provide the note and let them handle signing.
        signed_txn = self._build_payment_transaction(
            sender=self.account.address,
            receiver=to,
            amount=self.MIN_TRANSACTION_FEE,
            note=note,
            params=params,
        )

        # Submit transaction
        txid = await self.algod.submit_transaction(signed_txn)

        # Wait for confirmation if requested
        confirmed_round = 0
        if options.wait_for_confirmation:
            tx_info = await self.algod.wait_for_confirmation(
                txid, rounds=options.timeout_rounds
            )
            confirmed_round = tx_info.confirmed_round or 0

        # Wait for indexer if requested
        if options.wait_for_indexer:
            await self.indexer.wait_for_indexer(
                txid, timeout_secs=options.indexer_timeout_secs
            )

        # Build sent message
        message = Message(
            id=txid,
            sender=self.account.address,
            recipient=to,
            content=content,
            timestamp=datetime.now(),
            confirmed_round=confirmed_round,
            direction=MessageDirection.SENT,
            reply_context=options.reply_context,
        )

        return SendResult(txid=txid, message=message)

    def _build_payment_transaction(
        self,
        sender: str,
        receiver: str,
        amount: int,
        note: bytes,
        params: "SuggestedParams",
    ) -> bytes:
        """
        Build a signed payment transaction.

        Note: This is a placeholder. Real implementations should use algosdk
        or another SDK to build and sign transactions.
        """
        raise NotImplementedError(
            "Transaction building must be implemented by the SDK user. "
            "Use algosdk or py-algorand-sdk to build and sign transactions."
        )

    # MARK: - Key Management

    async def discover_key(self, address: str) -> DiscoveredKey:
        """
        Discover a user's encryption public key from their transaction history.

        Args:
            address: The user's Algorand address.

        Returns:
            DiscoveredKey with public key and verification status.

        Raises:
            PublicKeyNotFoundError: If no chat history exists.
        """
        # Check cache first
        cached = self.public_key_cache.retrieve(address)
        if cached is not None:
            return DiscoveredKey(public_key=cached, is_verified=False)

        # Search for transactions from this address
        transactions = await self.indexer.search_transactions(address, limit=200)

        for tx in transactions:
            # Only look at transactions sent by this address
            if tx.sender != address:
                continue

            if not tx.note or not is_chat_message(tx.note):
                continue

            try:
                envelope = decode_envelope(tx.note)
                # Extract sender's public key from envelope
                from .keys import public_key_to_bytes

                public_key = public_key_to_bytes(envelope.sender_public_key)

                # Cache for future lookups
                self.public_key_cache.store(address, public_key)

                return DiscoveredKey(public_key=public_key, is_verified=False)
            except Exception:
                continue

        raise PublicKeyNotFoundError(address)

    async def fetch_public_key(self, address: str) -> bytes:
        """
        Fetch a user's encryption public key.

        This is a convenience wrapper around discover_key that returns just the key bytes.

        Args:
            address: The user's Algorand address.

        Returns:
            The X25519 public key (32 bytes).

        Raises:
            PublicKeyNotFoundError: If no chat history exists.
        """
        discovered = await self.discover_key(address)
        return discovered.public_key

    async def publish_key(self) -> str:
        """
        Publish this account's encryption key to the blockchain.

        This creates a zero-value self-payment transaction containing the
        encryption public key, allowing others to discover it.

        Returns:
            The transaction ID.
        """
        # Create a self-encrypted message containing the key
        from .keys import public_key_from_bytes

        envelope = encrypt_message(
            '{"type": "key-publish"}',
            self.account.encryption_private_key,
            self.account.encryption_public_key,
            self.account.encryption_public_key,  # Self-encrypt
        )

        note = encode_envelope(envelope)
        params = await self.algod.get_suggested_params()

        signed_txn = self._build_payment_transaction(
            sender=self.account.address,
            receiver=self.account.address,  # Self-payment
            amount=0,
            note=note,
            params=params,
        )

        return await self.algod.submit_transaction(signed_txn)

    # MARK: - Account Info

    async def balance(self) -> int:
        """
        Get the account balance in microAlgos.

        Returns:
            Balance in microAlgos.
        """
        info = await self.algod.get_account_info(self.account.address)
        return info.amount

    # MARK: - Cache Management

    async def clear_cache(self) -> None:
        """Clear all cached data (messages and public keys)."""
        if self.message_cache:
            await self.message_cache.clear()
        self.public_key_cache.clear()

    async def clear_cache_for(self, participant: str) -> None:
        """Clear cached data for a specific conversation."""
        if self.message_cache:
            await self.message_cache.clear_for(participant)
        self.public_key_cache.invalidate(participant)

    def invalidate_cached_public_key(self, address: str) -> None:
        """Invalidate a cached public key."""
        self.public_key_cache.invalidate(address)

    # MARK: - Private Helpers

    async def _get_recipient_key(self, address: str) -> bytes:
        """Get recipient's public key, checking cache first."""
        if address == self.account.address:
            return self.account.public_key_bytes

        cached = self.public_key_cache.retrieve(address)
        if cached is not None:
            return cached

        discovered = await self.discover_key(address)
        return discovered.public_key

    def _parse_messages(self, transactions: List[NoteTransaction]) -> List[Message]:
        """Parse and decrypt messages from transactions."""
        messages: List[Message] = []

        for tx in transactions:
            if not tx.note or not is_chat_message(tx.note):
                continue

            try:
                envelope = decode_envelope(tx.note)

                # Determine direction
                if tx.sender == self.account.address:
                    direction = MessageDirection.SENT
                else:
                    direction = MessageDirection.RECEIVED

                # Decrypt
                from .keys import public_key_to_bytes

                decrypted = decrypt_message(
                    envelope,
                    self.account.encryption_private_key,
                    self.account.encryption_public_key,
                )

                if decrypted is None:
                    continue  # Key-publish or unrelated message

                # Build reply context if present
                reply_context = None
                if decrypted.reply_to_id:
                    reply_context = ReplyContext(
                        message_id=decrypted.reply_to_id,
                        preview=decrypted.reply_to_preview or "",
                    )

                messages.append(
                    Message(
                        id=tx.txid,
                        sender=tx.sender,
                        recipient=tx.receiver,
                        content=decrypted.text,
                        timestamp=datetime.fromtimestamp(tx.round_time),
                        confirmed_round=tx.confirmed_round,
                        direction=direction,
                        reply_context=reply_context,
                    )
                )
            except Exception:
                # Skip messages that can't be decrypted
                continue

        return messages
