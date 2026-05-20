"""Generic detection helpers: entropy and recursive string extraction."""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterator
from typing import Any


def shannon_entropy(text: str) -> float:
    """Return the Shannon entropy (bits per character) of ``text``."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def iter_strings(obj: Any, *, include_keys: bool = True) -> Iterator[str]:
    """Yield every string node reachable inside a JSON-like structure.

    Used to deep-walk a tool's ``inputSchema`` so a rule inspects nested
    fields (``enum``, ``examples``, ``$comment``, property descriptions) and
    not just the top-level description.
    """
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for key, value in obj.items():
            if include_keys and isinstance(key, str):
                yield key
            yield from iter_strings(value, include_keys=include_keys)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            yield from iter_strings(item, include_keys=include_keys)


__all__ = ["iter_strings", "shannon_entropy"]
