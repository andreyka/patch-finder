"""Prompt compaction logic for the new agent."""

from __future__ import annotations

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


def build_prompt_that_fits(
    messages: list[dict[str, str]],
    debug: bool = False
) -> tuple[list[dict[str, str]], int]:
    """Return a prompt trimmed to respect model context limits.
    
    This function ensures the prompt fits within MAX_MODEL_LEN by:
    1. Keeping system and initial user messages
    2. Limiting tool messages to MAX_TOOL_MSGS most recent
    3. Truncating large tool responses to TOOL_TRUNC_TOK
    4. Dropping older non-tool messages if needed
    
    Args:
        messages: The full list of message dictionaries.
        debug: Whether to print debug information.
        
    Returns:
        A tuple of (trimmed_messages, available_tokens_for_completion).
    """
    # Keep system and initial user messages intact
    system_and_initial_messages = messages[:2]
    subsequent_messages = messages[2:]
    
    # Separate tool and non-tool messages for selective trimming
    non_tool_messages = [m for m in subsequent_messages if m.get("role") != "tool"]
    tool_messages = [m for m in subsequent_messages if m.get("role") == "tool"]

    # Limit tool messages to most recent ones
    tool_messages = tool_messages[-MAX_TOOL_MSGS:]
    
    # Truncate large tool message content
    compact_tools: list[dict[str, str]] = []
    for message in tool_messages:
        content = message.get("content") or ""
        if token_count(content) > TOOL_TRUNC_TOK:
            truncated = truncate_to_token_cap(content, TOOL_TRUNC_TOK)
            new_message = dict(message)
            new_message["content"] = truncated
            compact_tools.append(new_message)
        else:
            compact_tools.append(message)

    # Iteratively drop messages until we fit within token budget
    while True:
        compact = system_and_initial_messages + non_tool_messages + compact_tools
        used = messages_token_sum(compact)
        available = MAX_MODEL_LEN - used - SAFETY_TOKENS
        
        if debug:
            print(f"[fit] prompt_tokens={used}, avail={available}")
        
        # Check if we have enough space or nothing left to drop
        has_enough_space = available >= MIN_COMPLETION_TOKENS
        nothing_to_drop = not non_tool_messages and not compact_tools
        
        if has_enough_space or nothing_to_drop:
            return compact, max(available, 0)
        
        # Drop oldest non-tool messages first, then tool messages
        if non_tool_messages:
            non_tool_messages = non_tool_messages[1:]
        elif compact_tools:
            compact_tools = compact_tools[1:]
        else:
            # Should never reach here due to nothing_to_drop check above
            break


__all__ = ["build_prompt_that_fits"]
