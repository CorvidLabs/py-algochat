"""Cross-implementation tests for AlgoChat.

These tests verify that Python can decrypt messages encrypted by Swift, TypeScript,
Rust, Kotlin, and Python implementations, ensuring full protocol compatibility
for both standard v1.0 and PSK v1.1 envelopes.
"""

from pathlib import Path
import json
import pytest
from algochat.keys import derive_keys_from_seed
from algochat.crypto import decrypt_message
from algochat.envelope import decode_envelope, is_chat_message
from algochat.psk_envelope import decode_psk_envelope, is_psk_message
from algochat.psk_crypto import decrypt_psk_message
from algochat.psk_ratchet import derive_psk_at_counter
from .test_vectors import (
    BOB_SEED_HEX,
    TEST_MESSAGES,
)


# Path to test-algochat repo with implementation envelopes
TEST_ALGOCHAT_DIR = Path(__file__).parent.parent.parent / "test-algochat"
SWIFT_ENVELOPES_DIR = TEST_ALGOCHAT_DIR / "test-envelopes-swift"
TS_ENVELOPES_DIR = TEST_ALGOCHAT_DIR / "test-envelopes-ts"
RUST_ENVELOPES_DIR = TEST_ALGOCHAT_DIR / "test-envelopes-rust"
KOTLIN_ENVELOPES_DIR = TEST_ALGOCHAT_DIR / "test-envelopes-kotlin"

# PSK envelope directories
SWIFT_PSK_DIR = TEST_ALGOCHAT_DIR / "test-envelopes-swift-psk"
TS_PSK_DIR = TEST_ALGOCHAT_DIR / "test-envelopes-ts-psk"
PYTHON_PSK_DIR = TEST_ALGOCHAT_DIR / "test-envelopes-python-psk"
RUST_PSK_DIR = TEST_ALGOCHAT_DIR / "test-envelopes-rust-psk"
KOTLIN_PSK_DIR = TEST_ALGOCHAT_DIR / "test-envelopes-kotlin-psk"

# Default test PSK (used if no metadata.json found)
TEST_PSK = bytes.fromhex(
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)


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

    def test_all_rust_messages_decrypt(self, bob_keys) -> None:
        """All Rust envelopes decrypt successfully."""
        if not _has_hex_files(RUST_ENVELOPES_DIR):
            pytest.skip("Rust envelopes not found")

        bob_private, bob_public = bob_keys
        passed = []
        failed = []

        for hex_file in RUST_ENVELOPES_DIR.glob("*.hex"):
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

        assert len(failed) == 0, f"Rust failures: {failed}"
        assert len(passed) >= 20, f"Only {len(passed)} Rust messages passed"

    def test_all_kotlin_messages_decrypt(self, bob_keys) -> None:
        """All Kotlin envelopes decrypt successfully."""
        if not _has_hex_files(KOTLIN_ENVELOPES_DIR):
            pytest.skip("Kotlin envelopes not found")

        bob_private, bob_public = bob_keys
        passed = []
        failed = []

        for hex_file in KOTLIN_ENVELOPES_DIR.glob("*.hex"):
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

        assert len(failed) == 0, f"Kotlin failures: {failed}"
        assert len(passed) >= 20, f"Only {len(passed)} Kotlin messages passed"


# --- Standard v1.0 envelope tests for Rust and Kotlin (issues #4, #9) ---

MESSAGE_KEYS = [
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
]


class TestRustEnvelopes:
    """Test decryption of Rust-generated envelopes."""

    @pytest.fixture(autouse=True)
    def skip_if_no_envelopes(self):
        """Skip tests if Rust envelopes don't exist."""
        if not _has_hex_files(RUST_ENVELOPES_DIR):
            pytest.skip("Rust envelopes not found")

    def get_envelope_files(self):
        """Get all Rust envelope hex files."""
        if not RUST_ENVELOPES_DIR.exists():
            return []
        return list(RUST_ENVELOPES_DIR.glob("*.hex"))

    def test_rust_envelopes_exist(self) -> None:
        """Verify Rust envelopes directory has files."""
        files = self.get_envelope_files()
        assert len(files) > 0, "No Rust envelope files found"

    @pytest.mark.parametrize("message_key", MESSAGE_KEYS)
    def test_decrypt_rust_envelope(self, bob_keys, message_key: str) -> None:
        """Decrypt each Rust-generated envelope."""
        hex_file = RUST_ENVELOPES_DIR / f"{message_key}.hex"

        if not hex_file.exists():
            pytest.skip(f"Rust envelope {message_key}.hex not found")

        bob_private, bob_public = bob_keys

        hex_data = hex_file.read_text().strip()
        envelope_bytes = bytes.fromhex(hex_data)

        assert is_chat_message(envelope_bytes), f"Invalid envelope for {message_key}"

        envelope = decode_envelope(envelope_bytes)
        result = decrypt_message(envelope, bob_private, bob_public)

        expected = get_expected_message(message_key)
        assert result is not None, f"Failed to decrypt Rust {message_key}"
        assert result.text == expected, f"Rust {message_key} mismatch"


class TestKotlinEnvelopes:
    """Test decryption of Kotlin-generated envelopes."""

    @pytest.fixture(autouse=True)
    def skip_if_no_envelopes(self):
        """Skip tests if Kotlin envelopes don't exist."""
        if not _has_hex_files(KOTLIN_ENVELOPES_DIR):
            pytest.skip("Kotlin envelopes not found")

    def get_envelope_files(self):
        """Get all Kotlin envelope hex files."""
        if not KOTLIN_ENVELOPES_DIR.exists():
            return []
        return list(KOTLIN_ENVELOPES_DIR.glob("*.hex"))

    def test_kotlin_envelopes_exist(self) -> None:
        """Verify Kotlin envelopes directory has files."""
        files = self.get_envelope_files()
        assert len(files) > 0, "No Kotlin envelope files found"

    @pytest.mark.parametrize("message_key", MESSAGE_KEYS)
    def test_decrypt_kotlin_envelope(self, bob_keys, message_key: str) -> None:
        """Decrypt each Kotlin-generated envelope."""
        hex_file = KOTLIN_ENVELOPES_DIR / f"{message_key}.hex"

        if not hex_file.exists():
            pytest.skip(f"Kotlin envelope {message_key}.hex not found")

        bob_private, bob_public = bob_keys

        hex_data = hex_file.read_text().strip()
        envelope_bytes = bytes.fromhex(hex_data)

        assert is_chat_message(envelope_bytes), f"Invalid envelope for {message_key}"

        envelope = decode_envelope(envelope_bytes)
        result = decrypt_message(envelope, bob_private, bob_public)

        expected = get_expected_message(message_key)
        assert result is not None, f"Failed to decrypt Kotlin {message_key}"
        assert result.text == expected, f"Kotlin {message_key} mismatch"


# --- PSK v1.1 envelope cross-implementation tests ---


def _load_psk_for_dir(psk_dir: Path) -> bytes:
    """Load PSK from metadata.json if present, otherwise use default TEST_PSK."""
    metadata_file = psk_dir / "metadata.json"
    if metadata_file.exists():
        metadata = json.loads(metadata_file.read_text())
        if "pskHex" in metadata:
            return bytes.fromhex(metadata["pskHex"])
    return TEST_PSK


def _has_hex_files(directory: Path) -> bool:
    """Check if a directory exists and contains .hex files."""
    return directory.exists() and len(list(directory.glob("*.hex"))) > 0


class TestSwiftPSKEnvelopes:
    """Test decryption of Swift-generated PSK envelopes."""

    @pytest.fixture(autouse=True)
    def skip_if_no_envelopes(self):
        """Skip tests if Swift PSK envelopes don't exist."""
        if not _has_hex_files(SWIFT_PSK_DIR):
            pytest.skip("Swift PSK envelopes not found")

    def get_envelope_files(self):
        """Get all Swift PSK envelope hex files."""
        if not SWIFT_PSK_DIR.exists():
            return []
        return list(SWIFT_PSK_DIR.glob("*.hex"))

    def test_swift_psk_envelopes_exist(self) -> None:
        """Verify Swift PSK envelopes directory has files."""
        files = self.get_envelope_files()
        assert len(files) > 0, "No Swift PSK envelope files found"

    @pytest.mark.parametrize("message_key", MESSAGE_KEYS)
    def test_decrypt_swift_psk_envelope(self, bob_keys, message_key: str) -> None:
        """Decrypt each Swift-generated PSK envelope."""
        hex_file = SWIFT_PSK_DIR / f"{message_key}.hex"

        if not hex_file.exists():
            pytest.skip(f"Swift PSK envelope {message_key}.hex not found")

        bob_private, bob_public = bob_keys
        initial_psk = _load_psk_for_dir(SWIFT_PSK_DIR)

        hex_data = hex_file.read_text().strip()
        envelope_bytes = bytes.fromhex(hex_data)

        assert is_psk_message(envelope_bytes), f"Invalid PSK envelope for {message_key}"

        envelope = decode_psk_envelope(envelope_bytes)
        current_psk = derive_psk_at_counter(initial_psk, envelope.ratchet_counter)
        result = decrypt_psk_message(envelope, bob_private, bob_public, current_psk)

        expected = get_expected_message(message_key)
        assert result is not None, f"Failed to decrypt Swift PSK {message_key}"
        assert result == expected, f"Swift PSK {message_key} mismatch"


class TestTypeScriptPSKEnvelopes:
    """Test decryption of TypeScript-generated PSK envelopes."""

    @pytest.fixture(autouse=True)
    def skip_if_no_envelopes(self):
        """Skip tests if TypeScript PSK envelopes don't exist."""
        if not _has_hex_files(TS_PSK_DIR):
            pytest.skip("TypeScript PSK envelopes not found")

    def get_envelope_files(self):
        """Get all TypeScript PSK envelope hex files."""
        if not TS_PSK_DIR.exists():
            return []
        return list(TS_PSK_DIR.glob("*.hex"))

    def test_ts_psk_envelopes_exist(self) -> None:
        """Verify TypeScript PSK envelopes directory has files."""
        files = self.get_envelope_files()
        assert len(files) > 0, "No TypeScript PSK envelope files found"

    @pytest.mark.parametrize("message_key", MESSAGE_KEYS)
    def test_decrypt_ts_psk_envelope(self, bob_keys, message_key: str) -> None:
        """Decrypt each TypeScript-generated PSK envelope."""
        hex_file = TS_PSK_DIR / f"{message_key}.hex"

        if not hex_file.exists():
            pytest.skip(f"TypeScript PSK envelope {message_key}.hex not found")

        bob_private, bob_public = bob_keys
        initial_psk = _load_psk_for_dir(TS_PSK_DIR)

        hex_data = hex_file.read_text().strip()
        envelope_bytes = bytes.fromhex(hex_data)

        assert is_psk_message(envelope_bytes), f"Invalid PSK envelope for {message_key}"

        envelope = decode_psk_envelope(envelope_bytes)
        current_psk = derive_psk_at_counter(initial_psk, envelope.ratchet_counter)
        result = decrypt_psk_message(envelope, bob_private, bob_public, current_psk)

        expected = get_expected_message(message_key)
        assert result is not None, f"Failed to decrypt TS PSK {message_key}"
        assert result == expected, f"TypeScript PSK {message_key} mismatch"


class TestPythonPSKEnvelopes:
    """Test decryption of Python-generated PSK envelopes."""

    @pytest.fixture(autouse=True)
    def skip_if_no_envelopes(self):
        """Skip tests if Python PSK envelopes don't exist."""
        if not _has_hex_files(PYTHON_PSK_DIR):
            pytest.skip("Python PSK envelopes not found")

    def get_envelope_files(self):
        """Get all Python PSK envelope hex files."""
        if not PYTHON_PSK_DIR.exists():
            return []
        return list(PYTHON_PSK_DIR.glob("*.hex"))

    def test_python_psk_envelopes_exist(self) -> None:
        """Verify Python PSK envelopes directory has files."""
        files = self.get_envelope_files()
        assert len(files) > 0, "No Python PSK envelope files found"

    @pytest.mark.parametrize("message_key", MESSAGE_KEYS)
    def test_decrypt_python_psk_envelope(self, bob_keys, message_key: str) -> None:
        """Decrypt each Python-generated PSK envelope."""
        hex_file = PYTHON_PSK_DIR / f"{message_key}.hex"

        if not hex_file.exists():
            pytest.skip(f"Python PSK envelope {message_key}.hex not found")

        bob_private, bob_public = bob_keys
        initial_psk = _load_psk_for_dir(PYTHON_PSK_DIR)

        hex_data = hex_file.read_text().strip()
        envelope_bytes = bytes.fromhex(hex_data)

        assert is_psk_message(envelope_bytes), f"Invalid PSK envelope for {message_key}"

        envelope = decode_psk_envelope(envelope_bytes)
        current_psk = derive_psk_at_counter(initial_psk, envelope.ratchet_counter)
        result = decrypt_psk_message(envelope, bob_private, bob_public, current_psk)

        expected = get_expected_message(message_key)
        assert result is not None, f"Failed to decrypt Python PSK {message_key}"
        assert result == expected, f"Python PSK {message_key} mismatch"


class TestRustPSKEnvelopes:
    """Test decryption of Rust-generated PSK envelopes."""

    @pytest.fixture(autouse=True)
    def skip_if_no_envelopes(self):
        """Skip tests if Rust PSK envelopes don't exist."""
        if not _has_hex_files(RUST_PSK_DIR):
            pytest.skip("Rust PSK envelopes not found")

    def get_envelope_files(self):
        """Get all Rust PSK envelope hex files."""
        if not RUST_PSK_DIR.exists():
            return []
        return list(RUST_PSK_DIR.glob("*.hex"))

    def test_rust_psk_envelopes_exist(self) -> None:
        """Verify Rust PSK envelopes directory has files."""
        files = self.get_envelope_files()
        assert len(files) > 0, "No Rust PSK envelope files found"

    @pytest.mark.parametrize("message_key", MESSAGE_KEYS)
    def test_decrypt_rust_psk_envelope(self, bob_keys, message_key: str) -> None:
        """Decrypt each Rust-generated PSK envelope."""
        hex_file = RUST_PSK_DIR / f"{message_key}.hex"

        if not hex_file.exists():
            pytest.skip(f"Rust PSK envelope {message_key}.hex not found")

        bob_private, bob_public = bob_keys
        initial_psk = _load_psk_for_dir(RUST_PSK_DIR)

        hex_data = hex_file.read_text().strip()
        envelope_bytes = bytes.fromhex(hex_data)

        assert is_psk_message(envelope_bytes), f"Invalid PSK envelope for {message_key}"

        envelope = decode_psk_envelope(envelope_bytes)
        current_psk = derive_psk_at_counter(initial_psk, envelope.ratchet_counter)
        result = decrypt_psk_message(envelope, bob_private, bob_public, current_psk)

        expected = get_expected_message(message_key)
        assert result is not None, f"Failed to decrypt Rust PSK {message_key}"
        assert result == expected, f"Rust PSK {message_key} mismatch"


class TestKotlinPSKEnvelopes:
    """Test decryption of Kotlin-generated PSK envelopes."""

    @pytest.fixture(autouse=True)
    def skip_if_no_envelopes(self):
        """Skip tests if Kotlin PSK envelopes don't exist."""
        if not _has_hex_files(KOTLIN_PSK_DIR):
            pytest.skip("Kotlin PSK envelopes not found")

    def get_envelope_files(self):
        """Get all Kotlin PSK envelope hex files."""
        if not KOTLIN_PSK_DIR.exists():
            return []
        return list(KOTLIN_PSK_DIR.glob("*.hex"))

    def test_kotlin_psk_envelopes_exist(self) -> None:
        """Verify Kotlin PSK envelopes directory has files."""
        files = self.get_envelope_files()
        assert len(files) > 0, "No Kotlin PSK envelope files found"

    @pytest.mark.parametrize("message_key", MESSAGE_KEYS)
    def test_decrypt_kotlin_psk_envelope(self, bob_keys, message_key: str) -> None:
        """Decrypt each Kotlin-generated PSK envelope."""
        hex_file = KOTLIN_PSK_DIR / f"{message_key}.hex"

        if not hex_file.exists():
            pytest.skip(f"Kotlin PSK envelope {message_key}.hex not found")

        bob_private, bob_public = bob_keys
        initial_psk = _load_psk_for_dir(KOTLIN_PSK_DIR)

        hex_data = hex_file.read_text().strip()
        envelope_bytes = bytes.fromhex(hex_data)

        assert is_psk_message(envelope_bytes), f"Invalid PSK envelope for {message_key}"

        envelope = decode_psk_envelope(envelope_bytes)
        current_psk = derive_psk_at_counter(initial_psk, envelope.ratchet_counter)
        result = decrypt_psk_message(envelope, bob_private, bob_public, current_psk)

        expected = get_expected_message(message_key)
        assert result is not None, f"Failed to decrypt Kotlin PSK {message_key}"
        assert result == expected, f"Kotlin PSK {message_key} mismatch"


class TestPSKCrossImplementationSummary:
    """Summary test to verify all PSK implementations are compatible."""

    PSK_DIRS = {
        "Swift": SWIFT_PSK_DIR,
        "TypeScript": TS_PSK_DIR,
        "Python": PYTHON_PSK_DIR,
        "Rust": RUST_PSK_DIR,
        "Kotlin": KOTLIN_PSK_DIR,
    }

    @pytest.mark.parametrize("impl_name", ["Swift", "TypeScript", "Python", "Rust", "Kotlin"])
    def test_all_psk_messages_decrypt(self, bob_keys, impl_name: str) -> None:
        """All PSK envelopes from a given implementation decrypt successfully."""
        psk_dir = self.PSK_DIRS[impl_name]
        if not _has_hex_files(psk_dir):
            pytest.skip(f"{impl_name} PSK envelopes not found")

        bob_private, bob_public = bob_keys
        initial_psk = _load_psk_for_dir(psk_dir)
        passed = []
        failed = []

        for hex_file in psk_dir.glob("*.hex"):
            message_key = hex_file.stem
            expected = get_expected_message(message_key)

            try:
                hex_data = hex_file.read_text().strip()
                envelope_bytes = bytes.fromhex(hex_data)
                envelope = decode_psk_envelope(envelope_bytes)
                current_psk = derive_psk_at_counter(initial_psk, envelope.ratchet_counter)
                result = decrypt_psk_message(
                    envelope, bob_private, bob_public, current_psk
                )

                if result == expected:
                    passed.append(message_key)
                else:
                    failed.append(message_key)
            except Exception as e:
                failed.append(f"{message_key}: {e}")

        assert len(failed) == 0, f"{impl_name} PSK failures: {failed}"
        assert len(passed) >= 20, f"Only {len(passed)} {impl_name} PSK messages passed"
