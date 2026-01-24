"""Test vectors for AlgoChat cross-implementation testing."""

# Test seeds (32-byte hex strings)
ALICE_SEED_HEX = "0000000000000000000000000000000000000000000000000000000000000001"
BOB_SEED_HEX = "0000000000000000000000000000000000000000000000000000000000000002"

# Expected X25519 public keys after HKDF derivation
ALICE_PUBLIC_KEY_HEX = "a04407c78ff19a0bbd578588d6100bca4ed7f89acfc600666dbab1d36061c064"
BOB_PUBLIC_KEY_HEX = "b43231dc85ba0781ad3df9b8f8458a5e6f4c1030d0526ace9540300e0398ae03"

# Test messages covering edge cases
TEST_MESSAGES = {
    "empty": "",
    "single_char": "X",
    "whitespace": "   \t\n   ",
    "numbers": "1234567890",
    "punctuation": "!@#$%^&*()_+-=[]{}\\|;':\",./<>?",
    "newlines": "Line 1\nLine 2\nLine 3",
    "emoji_simple": "Hello 👋 World 🌍",
    "emoji_zwj": "Family: 👨‍👩‍👧‍👦",
    "chinese": "你好世界 - Hello World",
    "arabic": "مرحبا بالعالم",
    "japanese": "こんにちは世界 カタカナ 漢字",
    "korean": "안녕하세요 세계",
    "accents": "Café résumé naïve",
    "cyrillic": "Привет мир",
    "json": '{"key": "value", "num": 42}',
    "html": '<div class="test">Content</div>',
    "url": "https://example.com/path?q=test&lang=en",
    "code": 'func hello() { print("Hi") }',
    "long_text": "The quick brown fox jumps over the lazy dog. " * 11,
    "max_payload": "A" * 882,
}
