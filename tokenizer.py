"""Token counting utilities with tiktoken fallback."""

from __future__ import annotations

from typing import Dict, List

try:
    import tiktoken
except Exception:  # pragma: no cover - optional dependency
    tiktoken = None  # type: ignore


if tiktoken:
    _ENCODER = tiktoken.get_encoding("cl100k_base")

    def token_count(text: str | None) -> int:
        return len(_ENCODER.encode(text or ""))
else:
    def token_count(text: str | None) -> int:  # type: ignore[no-redef]
        content = text or ""
        return max(1, len(content) // 4)


def message_token_count(message: Dict[str, str]) -> int:
    return 4 + token_count(message.get("content"))


def messages_token_sum(messages: List[Dict[str, str]]) -> int:
    return sum(message_token_count(m) for m in messages)


def truncate_to_token_cap(text: str, cap_tokens: int, marker: str = "...[truncated]") -> str:
    if cap_tokens <= 0:
        return ""
    low, high, best = 0, len(text), text
    while low <= high:
        mid = (low + high) // 2
        candidate = text[:mid]
        if token_count(candidate) <= cap_tokens:
            best = candidate
            low = mid + 1
        else:
            high = mid - 1
    return best if best == text else best + marker


__all__ = [
    "token_count",
    "message_token_count",
    "messages_token_sum",
    "truncate_to_token_cap",
]

