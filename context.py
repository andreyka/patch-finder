"""Prompt compaction logic for the new agent."""

from __future__ import annotations

from typing import Dict, List, Tuple

try:
    from .config import (
        MAX_MODEL_LEN,
        MAX_TOOL_MSGS,
        MIN_COMPLETION_TOKENS,
        SAFETY_TOKENS,
        TOOL_TRUNC_TOK,
    )
    from .tokenizer import (
        messages_token_sum,
        token_count,
        truncate_to_token_cap,
    )
except ImportError:  # pragma: no cover - script execution fallback
    from config import (
        MAX_MODEL_LEN,
        MAX_TOOL_MSGS,
        MIN_COMPLETION_TOKENS,
        SAFETY_TOKENS,
        TOOL_TRUNC_TOK,
    )
    from tokenizer import (
        messages_token_sum,
        token_count,
        truncate_to_token_cap,
    )


def build_prompt_that_fits(messages: List[Dict[str, str]], debug: bool = False) -> Tuple[List[Dict[str, str]], int]:
    """Return a prompt trimmed to respect model context limits."""

    base = messages[:2]
    remainder = messages[2:]
    non_tool = [m for m in remainder if m.get("role") != "tool"]
    tool_messages = [m for m in remainder if m.get("role") == "tool"]

    tool_messages = tool_messages[-MAX_TOOL_MSGS:]
    compact_tools: List[Dict[str, str]] = []
    for message in tool_messages:
        content = message.get("content") or ""
        if token_count(content) > TOOL_TRUNC_TOK:
            truncated = truncate_to_token_cap(content, TOOL_TRUNC_TOK)
            new_message = dict(message)
            new_message["content"] = truncated
            compact_tools.append(new_message)
        else:
            compact_tools.append(message)

    while True:
        compact = base + non_tool + compact_tools
        used = messages_token_sum(compact)
        available = MAX_MODEL_LEN - used - SAFETY_TOKENS
        if debug:
            print(f"[fit] prompt_tokens={used}, avail={available}")
        if available >= MIN_COMPLETION_TOKENS or (not non_tool and not compact_tools):
            return compact, max(available, 0)
        if non_tool:
            non_tool = non_tool[1:]
            continue
        if compact_tools:
            compact_tools = compact_tools[1:]
            continue


__all__ = ["build_prompt_that_fits"]
