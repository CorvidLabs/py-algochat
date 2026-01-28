"""PSK exchange URI handling for sharing pre-shared keys."""

import base64
from urllib.parse import urlencode, urlparse, parse_qs


def create_psk_exchange_uri(
    address: str,
    psk: bytes,
    label: str = None,
) -> str:
    """Create a PSK exchange URI for sharing a pre-shared key.

    Format: algochat-psk://v1?addr=...&psk=<base64url>&label=...

    Args:
        address: The Algorand address.
        psk: The pre-shared key (32 bytes).
        label: Optional human-readable label.

    Returns:
        The PSK exchange URI string.
    """
    psk_b64 = base64.urlsafe_b64encode(psk).rstrip(b"=").decode("ascii")

    params = {"addr": address, "psk": psk_b64}
    if label is not None:
        params["label"] = label

    query = urlencode(params)
    return f"algochat-psk://v1?{query}"


def parse_psk_exchange_uri(uri: str) -> dict:
    """Parse a PSK exchange URI.

    Args:
        uri: The PSK exchange URI string.

    Returns:
        Dictionary with keys: address, psk (bytes), label (optional).

    Raises:
        ValueError: If the URI is invalid.
    """
    parsed = urlparse(uri)

    if parsed.scheme != "algochat-psk":
        raise ValueError(f"Invalid scheme: {parsed.scheme}")

    if parsed.netloc != "v1":
        raise ValueError(f"Invalid version: {parsed.netloc}")

    params = parse_qs(parsed.query)

    if "addr" not in params:
        raise ValueError("Missing addr parameter")

    if "psk" not in params:
        raise ValueError("Missing psk parameter")

    address = params["addr"][0]

    # Decode base64url PSK (add padding back)
    psk_b64 = params["psk"][0]
    padding = 4 - len(psk_b64) % 4
    if padding != 4:
        psk_b64 += "=" * padding
    psk = base64.urlsafe_b64decode(psk_b64)

    result = {"address": address, "psk": psk}

    if "label" in params:
        result["label"] = params["label"][0]

    return result
