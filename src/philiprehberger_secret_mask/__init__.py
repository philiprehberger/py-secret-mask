"""Automatically detect and mask secrets in strings and dicts."""

from __future__ import annotations

import re

__all__ = ["is_secret_key", "mask_value", "mask_secrets"]

_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"pk-[A-Za-z0-9]{20,}"),
    re.compile(r"key-[A-Za-z0-9]{20,}"),
    re.compile(r"token-[A-Za-z0-9]{20,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
    re.compile(r"Basic\s+[A-Za-z0-9+/]+=*", re.IGNORECASE),
    re.compile(r"://[^:]+:[^@]+@"),
]

_SECRET_KEY_NAMES: set[str] = {
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "auth",
    "credential",
    "private_key",
    "access_key",
}


def is_secret_key(key: str) -> bool:
    """Check if a key name suggests it holds a secret value.

    Performs case-insensitive substring matching against known secret
    key name patterns.
    """
    lower = key.lower()
    return any(pattern in lower for pattern in _SECRET_KEY_NAMES)


def mask_value(value: str, *, mask_char: str = "*", reveal_last: int = 4) -> str:
    """Mask a string value, optionally revealing the last few characters.

    Args:
        value: The string to mask.
        mask_char: Character used for masking.
        reveal_last: Number of trailing characters to leave visible.

    Returns:
        The masked string.
    """
    if len(value) <= reveal_last:
        return mask_char * len(value)
    masked_length = len(value) - reveal_last
    return mask_char * masked_length + value[-reveal_last:]


def mask_secrets(
    data: str | dict[str, object] | list[object],
    *,
    mask_char: str = "*",
    reveal_last: int = 4,
) -> str | dict[str, object] | list[object]:
    """Detect and mask secrets in strings, dicts, or lists.

    For strings, scans for known secret patterns (API keys, bearer tokens,
    basic auth, connection strings) and replaces matches with masked values.

    For dicts, recursively inspects keys and masks values whose key names
    match known secret patterns.

    For lists, recursively processes each element.

    Args:
        data: The input to scan and mask.
        mask_char: Character used for masking.
        reveal_last: Number of trailing characters to leave visible.

    Returns:
        The input with detected secrets masked, preserving the original type.
    """
    if isinstance(data, str):
        result = data
        for pattern in _SECRET_PATTERNS:
            result = pattern.sub(
                lambda m: mask_value(m.group(), mask_char=mask_char, reveal_last=reveal_last),
                result,
            )
        return result

    if isinstance(data, dict):
        masked: dict[str, object] = {}
        for key, value in data.items():
            if is_secret_key(key) and isinstance(value, str):
                masked[key] = mask_value(value, mask_char=mask_char, reveal_last=reveal_last)
            elif isinstance(value, (dict, list, str)):
                masked[key] = mask_secrets(value, mask_char=mask_char, reveal_last=reveal_last)
            else:
                masked[key] = value
        return masked

    if isinstance(data, list):
        return [
            mask_secrets(item, mask_char=mask_char, reveal_last=reveal_last)
            if isinstance(item, (str, dict, list))
            else item
            for item in data
        ]

    return data
