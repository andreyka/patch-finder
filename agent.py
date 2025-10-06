"""Main loop for the new agent implementation."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional

from openai import OpenAI

package_dir = os.path.dirname(os.path.abspath(__file__))
if package_dir not in sys.path:
    sys.path.insert(0, package_dir)

from bootstrap import bootstrap_evidence
from config import (
    AUTO_EXPAND_COMMITS,
    BOOTSTRAP,
    COMMIT_EXPAND_LIMIT,
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    NO_PROGRESS_PATIENCE,
    NO_PROGRESS_WINDOW,
    TOOL_CALL_DELAY_SEC,
)
from context import build_prompt_that_fits
from progress import ProgressGuard
from prompt import SYSTEM_PROMPT_TEMPLATE
from tokenizer import messages_token_sum
from tools import (
    COMMIT_PATTERNS,
    TOOLS,
    extract_commit_links,
    tool_fetch_url,
    tool_web_search,
)

def _client(base_url: Optional[str]) -> OpenAI:
    """Create an OpenAI client with the specified base URL.
    
    Args:
        base_url: The base URL for the OpenAI API, or None for default.
        
    Returns:
        An initialized OpenAI client instance.
    """
    return OpenAI(
        base_url=base_url or DEFAULT_BASE_URL,
        api_key=os.environ.get("OPENAI_API_KEY", "sk-local")
    )


def _call_chat(
    client: OpenAI,
    model: str,
    messages: List[Dict[str, Any]],
    tools: List[Dict[str, Any]],
    max_tokens: int,
    debug: bool,
) -> Any:
    """Call the chat completion API with the given parameters.
    
    Args:
        client: The OpenAI client instance.
        model: The model name to use.
        messages: List of message dictionaries.
        tools: List of available tools.
        max_tokens: Maximum tokens for completion.
        debug: Whether to print debug information.
        
    Returns:
        The chat completion response.
    """
    mt = max(1, int(max_tokens))
    if debug:
        token_sum = messages_token_sum(messages)
        print(f"[chat] send: prompt_tokens={token_sum}, max_tokens={mt}")
    return client.chat.completions.create(
        model=model,
        messages=messages,
        tools=tools,
        tool_choice="auto",
        temperature=0,
        top_p=1,
        max_tokens=mt,
    )


def run_agent(
    cve_id: str,
    model: Optional[str],
    base_url: Optional[str],
    steps: int,
    debug: bool
) -> Dict[str, Any]:
    """Run the agent to find the fix commit for a CVE.
    
    Args:
        cve_id: The CVE identifier (e.g., 'CVE-2025-0762').
        model: The model name to use, or None for default.
        base_url: The API base URL, or None for default.
        steps: Maximum number of interaction rounds.
        debug: Whether to print debug information.
        
    Returns:
        A dictionary containing the CVE information and fix commit,
        or an error structure if the fix cannot be found.
    """
    client = _client(base_url)
    model_name = model or DEFAULT_MODEL

    system_prompt = SYSTEM_PROMPT_TEMPLATE.replace("<<CVE_ID>>", cve_id)
    if debug:
        print("=== System Prompt ===")
        print(system_prompt)
        print("=====================\n")

    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Find the official upstream fix commit for {cve_id}."},
    ]

    if BOOTSTRAP:
        if debug:
            print("[bootstrap] prefetching key sources...")
        boot = bootstrap_evidence(cve_id, debug=debug)
        messages.append({"role": "user", "content": boot})

    search_cache: Dict[str, str] = {}
    fetch_cache: Dict[str, str] = {}
    seen_commit_urls: Dict[str, int] = {}
    have_authority = False
    guard = ProgressGuard(NO_PROGRESS_WINDOW, NO_PROGRESS_PATIENCE)

    def tool_signature() -> str:
        """Generate a signature from recent tool messages.
        
        Returns:
            A string signature based on the last 3 tool messages.
        """
        last = [m for m in messages if m.get("role") == "tool"][-3:]
        return "|".join(
            f"{m.get('name')}:{(m.get('content') or '')[:64]}" for m in last
        )

    def add_tool_message(name: str, tool_call_id: str, content: str) -> None:
        """Add a tool response message and update tracking state.
        
        Args:
            name: The name of the tool that was called.
            tool_call_id: The unique identifier for this tool call.
            content: The content returned by the tool.
        """
        nonlocal have_authority
        if (
            "nvd.nist.gov/vuln/detail" in content
            or ("github.com/" in content and 
                "/security/advisories/" in content)
            or "osv.dev" in content
            or "api.osv.dev" in content
            or "github.com/advisories" in content
            or "issues.chromium.org" in content
            or "crbug.com" in content
            or "bugs.chromium.org" in content
        ):
            have_authority = True
        for url in re.findall(r"https?://[^\s)]+", content):
            for pattern in COMMIT_PATTERNS:
                if pattern.search(url):
                    seen_commit_urls[url] = seen_commit_urls.get(url, 0) + 1
        messages.append({
            "role": "tool",
            "tool_call_id": tool_call_id,
            "name": name,
            "content": content
        })

        if AUTO_EXPAND_COMMITS:
            new_commits = [
                u for u in extract_commit_links(content)
                if u not in fetch_cache
            ]
            if new_commits:
                expanded_payloads: List[str] = []
                for commit_url in new_commits[:COMMIT_EXPAND_LIMIT]:
                    expanded = tool_fetch_url(commit_url, debug=debug)
                    fetch_cache[commit_url] = expanded
                    expanded_payloads.append(expanded)
                    for pattern in COMMIT_PATTERNS:
                        if pattern.search(commit_url):
                            seen_commit_urls[commit_url] = (
                                seen_commit_urls.get(commit_url, 0) + 1
                            )
                if expanded_payloads:
                    messages.append({
                        "role": "user",
                        "content": (
                            "AUTO-EXPANDED COMMIT PAGES:\n\n" +
                            "\n\n".join(expanded_payloads)
                        ),
                    })

    for step in range(1, max(1, steps) + 1):
        if debug:
            print(f"[step {step}] chat | model={model_name}")

        have_full_sha = any(
            re.search(r"/commit/([0-9a-f]{40})(?:\b|$)", url)
            for url in seen_commit_urls
        )
        if have_full_sha and have_authority:
            messages.append({
                "role": "user",
                "content": (
                    "You already have a full 40-char SHA commit URL and "
                    "at least one authority (NVD/GHSA/OSV). "
                    "Output the STRICT JSON now, with all required fields."
                ),
            })

        prompt_messages, available_tokens = build_prompt_that_fits(messages, debug=debug)
        max_tokens = max(1, available_tokens)

        try:
            response = _call_chat(
                client, model_name, prompt_messages, TOOLS, max_tokens, debug
            )
        except Exception as exc:
            if debug:
                print(f"[chat error] {exc}")
            minimal = (
                messages[:2] +
                [m for m in messages[2:] if m.get("role") == "tool"][-10:]
            )
            prompt_messages, available_tokens = build_prompt_that_fits(
                minimal, debug=debug
            )
            try:
                response = _call_chat(
                    client,
                    model_name,
                    prompt_messages,
                    TOOLS,
                    min(512, available_tokens),
                    debug
                )
            except Exception as hard_exc:
                if debug:
                    print(f"[chat hard fail] {hard_exc}")
                return {
                    "cve_id": cve_id,
                    "date": "YYYY-MM-DD",
                    "description": "No description available.",
                    "commit_hash": "None",
                    "error": "Unable to find official fix commit",
                    "reason": "Model/server refused due to context limits",
                }

        message = response.choices[0].message

        if getattr(message, "tool_calls", None):
            for tool_call in message.tool_calls:
                name = tool_call.function.name
                try:
                    args = json.loads(tool_call.function.arguments or "{}")
                except Exception:
                    args = {}

                if name == "web_search":
                    query = (args.get("query") or "").strip()
                    if not query:
                        output = "ERROR: empty query."
                    else:
                        output = search_cache.get(query)
                        if output is None:
                            output = tool_web_search(query, debug=debug)
                            search_cache[query] = output
                    add_tool_message("web_search", tool_call.id, output)

                elif name == "fetch_url":
                    url = (args.get("url") or "").strip()
                    if not url:
                        output = "ERROR: empty url."
                    else:
                        cached = fetch_cache.get(url)
                        if cached and not cached.startswith("ERROR:"):
                            output = f"NOTE: URL {url} already fetched. Use existing info."
                        else:
                            output = tool_fetch_url(url, debug=debug)
                            fetch_cache[url] = output
                    add_tool_message("fetch_url", tool_call.id, output)

                else:
                    add_tool_message(name, tool_call.id, f"ERROR: unknown tool {name}")

                time.sleep(TOOL_CALL_DELAY_SEC)

            signature = tool_signature()
            guard.note(signature)
            if debug:
                print(f"[progress] sig='{signature[:96]}', stalls={guard.stalls}")
            if guard.should_finalize():
                messages.append(
                    {
                        "role": "user",
                        "content": "Stop calling tools. Use existing evidence and output STRICT JSON now.",
                    }
                )
            continue

        content = message.content or ""
        if debug:
            print(f"[assistant] {content[:4000]}\n")
        try:
            return json.loads(content)
        except Exception:
            messages.append({"role": "assistant", "content": content[:2000]})
            messages.append({"role": "user", "content": "Respond now as STRICT JSON only. Do not call tools."})
            continue

    return {
        "cve_id": cve_id,
        "date": "YYYY-MM-DD",
        "description": "No description available.",
        "commit_hash": "None",
        "error": "Unable to find official fix commit",
        "reason": "Reached max steps without a valid JSON answer",
    }


__all__ = ["run_agent", "TOOLS", "build_arg_parser", "main"]

def build_arg_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser.
    
    Returns:
        An ArgumentParser configured with all CLI options.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Find the official upstream fix commit for a CVE "
            "(128k context agent)."
        )
    )
    parser.add_argument("cve_id")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--steps", type=int, default=60)
    parser.add_argument("--debug", action="store_true")
    return parser


def main() -> None:
    """Main entry point for the CLI."""
    parser = build_arg_parser()
    args = parser.parse_args()
    result = run_agent(
        args.cve_id, args.model, args.base_url, args.steps, args.debug
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

