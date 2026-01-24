"""Cross-implementation tests for AlgoChat.

These tests verify that Python can decrypt messages encrypted by Swift and TypeScript
implementations, ensuring full protocol compatibility.
"""

from pathlib import Path
import pytest
from algochat.keys import derive_keys_from_seed
from algochat.crypto import decrypt_message
from algochat.envelope import decode_envelope, is_chat_message
from .test_vectors import (
    BOB_SEED_HEX,
    TEST_MESSAGES,
)


# Path to test-algochat repo with Swift/TS envelopes
TEST_ALGOCHAT_DIR = Path(__file__).parent.parent.parent / "test-algochat"
SWIFT_ENVELOPES_DIR = TEST_ALGOCHAT_DIR / "test-envelopes-swift"
TS_ENVELOPES_DIR = TEST_ALGOCHAT_DIR / "test-envelopes-ts"


def get_expected_message(key: str) -> str:
    """Get expected message for a test key."""
    return TEST_MESSAGES.get(key, "")


@pytest.fixture
def bob_keys():
    """Bob's key pair for decryption."""
    seed = bytes.fromhex(BOB_SEED_HEX)
    return derive_keys_from_seed(seed)


class TestSwiftEnvelopes:
    """Test decryption of Swift-generated envelopes."""

    @pytest.fixture(autouse=True)
    def skip_if_no_envelopes(self):
        """Skip tests if Swift envelopes don't exist."""
        if not SWIFT_ENVELOPES_DIR.exists():
            pytest.skip("Swift envelopes not found")

    def get_envelope_files(self):
        """Get all Swift envelope hex files."""
        if not SWIFT_ENVELOPES_DIR.exists():
            return []
        return list(SWIFT_ENVELOPES_DIR.glob("*.hex"))

    def test_swift_envelopes_exist(self) -> None:
        """Verify Swift envelopes directory has files."""
        files = self.get_envelope_files()
        assert len(files) > 0, "No Swift envelope files found"

    @pytest.mark.parametrize(
        "message_key",
        [
            "empty",
            "single_char",
            "whitespace",
            "numbers",
            "punctuation",
            "newlines",
            "emoji_simple",
            "emoji_zwj",
            "chinese",
            "arabic",
            "japanese",
            "korean",
            "accents",
            "cyrillic",
            "json",
            "html",
            "url",
            "code",
            "long_text",
            "max_payload",
        ],
    )
    def test_decrypt_swift_envelope(self, bob_keys, message_key: str) -> None:
        """Decrypt each Swift-generated envelope."""
        hex_file = SWIFT_ENVELOPES_DIR / f"{message_key}.hex"

        if not hex_file.exists():
            pytest.skip(f"Swift envelope {message_key}.hex not found")

        bob_private, bob_public = bob_keys

        # Read hex-encoded envelope
        hex_data = hex_file.read_text().strip()
        envelope_bytes = bytes.fromhex(hex_data)

        assert is_chat_message(envelope_bytes), f"Invalid envelope for {message_key}"

        envelope = decode_envelope(envelope_bytes)
        result = decrypt_message(envelope, bob_private, bob_public)

        expected = get_expected_message(message_key)
        assert result is not None, f"Failed to decrypt Swift {message_key}"
        assert result.text == expected, f"Swift {message_key} mismatch"


class TestTypeScriptEnvelopes:
    """Test decryption of TypeScript-generated envelopes."""

    @pytest.fixture(autouse=True)
    def skip_if_no_envelopes(self):
        """Skip tests if TypeScript envelopes don't exist."""
        if not TS_ENVELOPES_DIR.exists():
            pytest.skip("TypeScript envelopes not found")

    def get_envelope_files(self):
        """Get all TypeScript envelope hex files."""
        if not TS_ENVELOPES_DIR.exists():
            return []
        return list(TS_ENVELOPES_DIR.glob("*.hex"))

    def test_ts_envelopes_exist(self) -> None:
        """Verify TypeScript envelopes directory has files."""
        files = self.get_envelope_files()
        assert len(files) > 0, "No TypeScript envelope files found"

    @pytest.mark.parametrize(
        "message_key",
        [
            "empty",
            "single_char",
            "whitespace",
            "numbers",
            "punctuation",
            "newlines",
            "emoji_simple",
            "emoji_zwj",
            "chinese",
            "arabic",
            "japanese",
            "korean",
            "accents",
            "cyrillic",
            "json",
            "html",
            "url",
            "code",
            "long_text",
            "max_payload",
        ],
    )
    def test_decrypt_ts_envelope(self, bob_keys, message_key: str) -> None:
        """Decrypt each TypeScript-generated envelope."""
        hex_file = TS_ENVELOPES_DIR / f"{message_key}.hex"

        if not hex_file.exists():
            pytest.skip(f"TypeScript envelope {message_key}.hex not found")

        bob_private, bob_public = bob_keys

        # Read hex-encoded envelope
        hex_data = hex_file.read_text().strip()
        envelope_bytes = bytes.fromhex(hex_data)

        assert is_chat_message(envelope_bytes), f"Invalid envelope for {message_key}"

        envelope = decode_envelope(envelope_bytes)
        result = decrypt_message(envelope, bob_private, bob_public)

        expected = get_expected_message(message_key)
        assert result is not None, f"Failed to decrypt TS {message_key}"
        assert result.text == expected, f"TypeScript {message_key} mismatch"


class TestCrossImplementationSummary:
    """Summary test to verify all implementations are compatible."""

    def test_all_swift_messages_decrypt(self, bob_keys) -> None:
        """All Swift envelopes decrypt successfully."""
        if not SWIFT_ENVELOPES_DIR.exists():
            pytest.skip("Swift envelopes not found")

        bob_private, bob_public = bob_keys
        passed = []
        failed = []

        for hex_file in SWIFT_ENVELOPES_DIR.glob("*.hex"):
            message_key = hex_file.stem
            expected = get_expected_message(message_key)

            try:
                hex_data = hex_file.read_text().strip()
                envelope_bytes = bytes.fromhex(hex_data)
                envelope = decode_envelope(envelope_bytes)
                result = decrypt_message(envelope, bob_private, bob_public)

                if result and result.text == expected:
                    passed.append(message_key)
                else:
                    failed.append(message_key)
            except Exception as e:
                failed.append(f"{message_key}: {e}")

        assert len(failed) == 0, f"Swift failures: {failed}"
        assert len(passed) >= 20, f"Only {len(passed)} Swift messages passed"

    def test_all_ts_messages_decrypt(self, bob_keys) -> None:
        """All TypeScript envelopes decrypt successfully."""
        if not TS_ENVELOPES_DIR.exists():
            pytest.skip("TypeScript envelopes not found")

        bob_private, bob_public = bob_keys
        passed = []
        failed = []

        for hex_file in TS_ENVELOPES_DIR.glob("*.hex"):
            message_key = hex_file.stem
            expected = get_expected_message(message_key)

            try:
                hex_data = hex_file.read_text().strip()
                envelope_bytes = bytes.fromhex(hex_data)
                envelope = decode_envelope(envelope_bytes)
                result = decrypt_message(envelope, bob_private, bob_public)

                if result and result.text == expected:
                    passed.append(message_key)
                else:
                    failed.append(message_key)
            except Exception as e:
                failed.append(f"{message_key}: {e}")

        assert len(failed) == 0, f"TypeScript failures: {failed}"
        assert len(passed) >= 20, f"Only {len(passed)} TypeScript messages passed"
