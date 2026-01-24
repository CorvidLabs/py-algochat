#!/usr/bin/env python3
"""Export Python-generated envelopes for cross-implementation testing."""

from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from algochat.keys import derive_keys_from_seed
from algochat.crypto import encrypt_message
from algochat.envelope import encode_envelope
from test_vectors import ALICE_SEED_HEX, BOB_SEED_HEX, TEST_MESSAGES


def main() -> None:
    """Export all test envelopes as hex files."""
    # Output directory
    output_dir = Path(__file__).parent.parent.parent / "test-algochat" / "test-envelopes-python"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Get key pairs
    alice_seed = bytes.fromhex(ALICE_SEED_HEX)
    bob_seed = bytes.fromhex(BOB_SEED_HEX)

    alice_private, alice_public = derive_keys_from_seed(alice_seed)
    _, bob_public = derive_keys_from_seed(bob_seed)

    print(f"Exporting {len(TEST_MESSAGES)} test envelopes to {output_dir}")

    for key, message in TEST_MESSAGES.items():
        envelope = encrypt_message(
            message,
            alice_private,
            alice_public,
            bob_public,
        )

        encoded = encode_envelope(envelope)
        hex_data = encoded.hex()

        output_file = output_dir / f"{key}.hex"
        output_file.write_text(hex_data)

        print(f"  {key}: {len(encoded)} bytes")

    print(f"\nExported {len(TEST_MESSAGES)} envelopes to {output_dir}")


if __name__ == "__main__":
    main()
