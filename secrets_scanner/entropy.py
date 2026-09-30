"""Shannon entropy and character-class helpers for spotting random-looking strings."""

import math
from collections import Counter

HEX_CHARS = frozenset("0123456789abcdefABCDEF")


def shannon_entropy(s: str) -> float:
    """Bits of entropy per character."""
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def char_classes(s: str) -> int:
    """How many of {lowercase, uppercase, digit} appear in s."""
    return (
        any(c.islower() for c in s)
        + any(c.isupper() for c in s)
        + any(c.isdigit() for c in s)
    )


def is_hex(s: str) -> bool:
    return bool(s) and all(c in HEX_CHARS for c in s)
