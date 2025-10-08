"""Patch finder AI agent workflow implementation."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Literal, Optional, TypedDict, Union

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


# Message role constants
MESSAGE_ROLE_TOOL = "tool"
MESSAGE_ROLE_USER = "user"
MESSAGE_ROLE_ASSISTANT = "assistant"
MESSAGE_ROLE_SYSTEM = "system"

# Context fallback constants
MINIMAL_CONTEXT_BASE_MESSAGES = 2
MINIMAL_CONTEXT_TOOL_MESSAGES = 10
MINIMAL_CONTEXT_MAX_TOKENS = 512

# Authority source patterns for verification
AUTHORITY_SOURCES = [
    "nvd.nist.gov/vuln/detail",
    "osv.dev",
    "api.osv.dev",
    "github.com/advisories",
    "issues.chromium.org",
    "crbug.com",
    "bugs.chromium.org",
]

GITHUB_SECURITY_ADVISORY_MARKERS = ("github.com/", "/security/advisories/")


class CommitSuccessResponse(TypedDict):
    """Successful commit identification response."""
    cve_id: str
    date: str
    description: str
    commit_hash: str


class CommitErrorResponse(TypedDict):
    """Error response when commit cannot be identified."""
    cve_id: str
    date: Literal["YYYY-MM-DD"]
    description: str
    commit_hash: Literal["None"]
    error: str
    reason: str


CommitResponse = Union[CommitSuccessResponse, CommitErrorResponse]


class PatchFinderAgent:
    """Agent class for finding fix commits for CVEs."""
    
    def __init__(
        self,
        cve_id: str,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        steps: int = 60,
        debug: bool = False,
    ):
        """Initialize the CVE Agent.
        
        Args:
            cve_id: The CVE identifier (e.g., 'CVE-2025-0762').
            model: The model name to use, or None for default.
            base_url: The API base URL, or None for default.
            steps: Maximum number of interaction rounds.
            debug: Whether to print debug information.
        """
        self.cve_id = cve_id
        self.model_name = model or DEFAULT_MODEL
        self.base_url = base_url or DEFAULT_BASE_URL
        self.steps = steps
        self.debug = debug
        
        # Initialize OpenAI client
        self.client = OpenAI(
            base_url=self.base_url,
            api_key=os.environ.get("OPENAI_API_KEY", "sk-local")
        )
        
        # Initialize state
        self.messages: List[Dict[str, Any]] = []
        self.search_cache: Dict[str, str] = {}
        self.fetch_cache: Dict[str, str] = {}
        self.seen_commit_urls: Dict[str, int] = {}
        self.have_authority = False
        self.guard = ProgressGuard(NO_PROGRESS_WINDOW, NO_PROGRESS_PATIENCE)
        
    def _call_chat(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        max_tokens: int,
    ) -> Any:
        """Call the chat completion API with the given parameters.
        
        Args:
            messages: List of message dictionaries.
            tools: List of available tools.
            max_tokens: Maximum tokens for completion.
            
        Returns:
            The chat completion response.
        """
        mt = max(1, int(max_tokens))
        if self.debug:
            token_sum = messages_token_sum(messages)
            print(f"[chat] send: prompt_tokens={token_sum}, max_tokens={mt}")
        return self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            tools=tools,
            tool_choice="auto",
            temperature=0,
            top_p=1,
            max_tokens=mt,
        )
    
    def _initialize_messages(self) -> None:
        """Initialize the message list with system and user prompts."""
        system_prompt = SYSTEM_PROMPT_TEMPLATE.replace("<<CVE_ID>>", self.cve_id)
        if self.debug:
            print("=== System Prompt ===")
            print(system_prompt)
            print("=====================\n")

        self.messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Find the official upstream fix commit for {self.cve_id}."},
        ]

        if BOOTSTRAP:
            if self.debug:
                print("[bootstrap] prefetching key sources...")
            boot = bootstrap_evidence(self.cve_id, debug=self.debug)
            self.messages.append({"role": "user", "content": boot})
    
    def _tool_signature(self) -> str:
        """Generate a signature from recent tool messages.
        
        Returns:
            A string signature based on the last 3 tool messages.
        """
        last = [m for m in self.messages if m.get("role") == "tool"][-3:]
        return "|".join(
            f"{m.get('name')}:{(m.get('content') or '')[:64]}" for m in last
        )
    
    def _is_authority_source(self, content: str) -> bool:
        """Check if content contains an authority source URL.
        
        Authority sources are official security databases and bug trackers
        that provide reliable information about vulnerabilities.
        
        Args:
            content: The content to check for authority source URLs.
            
        Returns:
            True if an authority source is found, False otherwise.
        """
        # Check for GitHub Security Advisory (requires both markers)
        if all(marker in content for marker in GITHUB_SECURITY_ADVISORY_MARKERS):
            return True
        
        # Check for other authority sources
        return any(source in content for source in AUTHORITY_SOURCES)
    
    def _add_tool_message(self, name: str, tool_call_id: str, content: str) -> None:
        """Add a tool response message and update tracking state.
        
        Args:
            name: The name of the tool that was called.
            tool_call_id: The unique identifier for this tool call.
            content: The content returned by the tool.
        """
        # Check if we've hit an authority source
        if self._is_authority_source(content):
            self.have_authority = True
            
        # Track commit URLs
        for url in re.findall(r"https?://[^\s)]+", content):
            for pattern in COMMIT_PATTERNS:
                if pattern.search(url):
                    self.seen_commit_urls[url] = self.seen_commit_urls.get(url, 0) + 1
                    
        self.messages.append({
            "role": MESSAGE_ROLE_TOOL,
            "tool_call_id": tool_call_id,
            "name": name,
            "content": content
        })

        # Auto-expand commits if enabled
        if AUTO_EXPAND_COMMITS:
            new_commits = [
                u for u in extract_commit_links(content)
                if u not in self.fetch_cache
            ]
            if new_commits:
                expanded_payloads: List[str] = []
                for commit_url in new_commits[:COMMIT_EXPAND_LIMIT]:
                    expanded = tool_fetch_url(commit_url, debug=self.debug)
                    self.fetch_cache[commit_url] = expanded
                    expanded_payloads.append(expanded)
                    for pattern in COMMIT_PATTERNS:
                        if pattern.search(commit_url):
                            self.seen_commit_urls[commit_url] = (
                                self.seen_commit_urls.get(commit_url, 0) + 1
                            )
                if expanded_payloads:
                    self.messages.append({
                        "role": MESSAGE_ROLE_USER,
                        "content": (
                            "AUTO-EXPANDED COMMIT PAGES:\n\n" +
                            "\n\n".join(expanded_payloads)
                        ),
                    })
    
    def _parse_tool_arguments(self, tool_call: Any) -> Dict[str, Any]:
        """Parse and repair tool call arguments.
        
        Args:
            tool_call: The tool call object from the API response.
            
        Returns:
            Parsed arguments dictionary, or empty dict if parsing fails.
        """
        name = tool_call.function.name
        try:
            return json.loads(tool_call.function.arguments or "{}")
        except Exception as e:
            # Try to repair common JSON errors (trailing commas, etc)
            raw_args = tool_call.function.arguments or "{}"
            try:
                # Remove trailing commas before closing braces/brackets
                repaired = re.sub(r',\s*}', '}', raw_args)
                repaired = re.sub(r',\s*]', ']', repaired)
                # Remove empty string keys like ,"" or ,""} 
                repaired = re.sub(r',\s*""\s*}', '}', repaired)
                repaired = re.sub(r',\s*""\s*]', ']', repaired)
                args = json.loads(repaired)
                if self.debug:
                    print(f"[tool_call_repair] Successfully repaired JSON for {name}")
                    print(f"[tool_call_repair] Original: {raw_args!r}")
                    print(f"[tool_call_repair] Repaired: {repaired!r}")
                return args
            except Exception:
                if self.debug:
                    print(f"[tool_call_error] Failed to parse arguments for {name}: {e}")
                    print(f"[tool_call_error] Raw arguments: {raw_args!r}")
                    print(f"[tool_call_error] Repair attempt also failed")
                return {}
    
    def _handle_web_search(self, tool_call: Any, args: Dict[str, Any]) -> None:
        """Handle a web_search tool call.
        
        Args:
            tool_call: The tool call object from the API response.
            args: Parsed arguments dictionary.
        """
        query = (args.get("query") or "").strip()
        if not query:
            output = "ERROR: empty query."
            if self.debug:
                print(f"[tool_call_error] web_search called with empty query")
                print(f"[tool_call_error] Parsed args: {args}")
                print(f"[tool_call_error] Raw arguments: {tool_call.function.arguments!r}")
        else:
            output = self.search_cache.get(query)
            if output is None:
                output = tool_web_search(query, debug=self.debug)
                self.search_cache[query] = output
        self._add_tool_message("web_search", tool_call.id, output)
    
    def _handle_fetch_url(self, tool_call: Any, args: Dict[str, Any]) -> None:
        """Handle a fetch_url tool call.
        
        Args:
            tool_call: The tool call object from the API response.
            args: Parsed arguments dictionary.
        """
        url = (args.get("url") or "").strip()
        if not url:
            output = "ERROR: empty url."
            if self.debug:
                print(f"[tool_call_error] fetch_url called with empty url")
                print(f"[tool_call_error] Parsed args: {args}")
                print(f"[tool_call_error] Raw arguments: {tool_call.function.arguments!r}")
        else:
            cached = self.fetch_cache.get(url)
            if cached and not cached.startswith("ERROR:"):
                output = f"NOTE: URL {url} already fetched. Use existing info."
            else:
                output = tool_fetch_url(url, debug=self.debug)
                self.fetch_cache[url] = output
        self._add_tool_message("fetch_url", tool_call.id, output)
    
    def _handle_unknown_tool(self, tool_call: Any) -> None:
        """Handle an unknown tool call.
        
        Args:
            tool_call: The tool call object from the API response.
        """
        name = tool_call.function.name
        output = f"ERROR: unknown tool {name}"
        if self.debug:
            print(f"[tool_call_error] Unknown tool: {name}")
            print(f"[tool_call_error] Raw arguments: {tool_call.function.arguments!r}")
        self._add_tool_message(name, tool_call.id, output)
    
    def _handle_tool_call(self, tool_call: Any) -> None:
        """Handle a single tool call.
        
        Args:
            tool_call: The tool call object from the API response.
        """
        name = tool_call.function.name
        args = self._parse_tool_arguments(tool_call)

        if name == "web_search":
            self._handle_web_search(tool_call, args)
        elif name == "fetch_url":
            self._handle_fetch_url(tool_call, args)
        else:
            self._handle_unknown_tool(tool_call)

        time.sleep(TOOL_CALL_DELAY_SEC)
    
    def _check_finalization_condition(self) -> bool:
        """Check if we should add a finalization message.
        
        Returns:
            True if finalization message was added, False otherwise.
        """
        have_full_sha = any(
            re.search(r"/commit/([0-9a-f]{40})(?:\b|$)", url)
            for url in self.seen_commit_urls
        )
        if have_full_sha and self.have_authority:
            self.messages.append({
                "role": MESSAGE_ROLE_USER,
                "content": (
                    "You have seen commit URLs and authority sources. "
                    "CRITICAL: Verify the commit is the FIX, not the last affected/vulnerable commit. "
                    "Check commit message for 'fix', 'patch', 'CVE-XXXX', or security terms. "
                    "Verify the diff removes vulnerable code. "
                    "If this is the last affected commit (vulnerable), search for the NEXT commit that fixes it. "
                    "Once verified, output the STRICT JSON with all required fields."
                ),
            })
            return True
        return False
    
    def _handle_tool_calls(self, message: Any) -> None:
        """Handle all tool calls in a message.
        
        Args:
            message: The message object containing tool calls.
        """
        for tool_call in message.tool_calls:
            self._handle_tool_call(tool_call)

        signature = self._tool_signature()
        self.guard.note(signature)
        if self.debug:
            # Show more readable progress info
            last_tools = [m for m in self.messages if m.get("role") == MESSAGE_ROLE_TOOL][-3:]
            tool_summary = []
            for m in last_tools:
                name = m.get('name', 'unknown')
                content = (m.get('content') or '')[:64]
                # Highlight errors in red-ish way
                if content.startswith("ERROR:"):
                    tool_summary.append(f"{name}:❌{content}")
                else:
                    tool_summary.append(f"{name}:✓")
            print(f"[progress] recent_tools=[{', '.join(tool_summary)}] stalls={self.guard.stalls}")
            print(f"[progress] signature='{signature[:120]}'")
        if self.guard.should_finalize():
            self.messages.append(
                {
                    "role": MESSAGE_ROLE_USER,
                    "content": "Stop calling tools. Use existing evidence and output STRICT JSON now.",
                }
            )
    
    def _create_error_response(self, reason: str) -> CommitErrorResponse:
        """Create an error response dictionary.
        
        Args:
            reason: The reason for the error.
            
        Returns:
            A CommitErrorResponse dictionary with error information.
        """
        return {
            "cve_id": self.cve_id,
            "date": "YYYY-MM-DD",
            "description": "No description available.",
            "commit_hash": "None",
            "error": "Unable to find official fix commit",
            "reason": reason,
        }
    
    def _build_minimal_messages(self) -> List[Dict[str, Any]]:
        """Build minimal message context with base messages and recent tool responses.
        
        This is used as a fallback when the full context is too large.
        
        Returns:
            A minimal list of messages for context reduction.
        """
        return (
            self.messages[:MINIMAL_CONTEXT_BASE_MESSAGES] +
            [m for m in self.messages[MINIMAL_CONTEXT_BASE_MESSAGES:] 
             if m.get("role") == MESSAGE_ROLE_TOOL][-MINIMAL_CONTEXT_TOOL_MESSAGES:]
        )
    
    def _call_chat_with_fallback(
        self,
        prompt_messages: List[Dict[str, Any]],
        max_tokens: int
    ) -> Any:
        """Call chat API with automatic fallback to minimal context on error.
        
        Args:
            prompt_messages: The messages to send to the API.
            max_tokens: Maximum tokens for completion.
            
        Returns:
            The chat completion response.
            
        Raises:
            Exception: If even the minimal context call fails.
        """
        try:
            return self._call_chat(prompt_messages, TOOLS, max_tokens)
        except Exception as exc:
            if self.debug:
                print(f"[chat error] {exc} - trying with minimal context")
            
            # Try with minimal context as fallback
            minimal_messages = self._build_minimal_messages()
            prompt_messages, available_tokens = build_prompt_that_fits(
                minimal_messages, debug=self.debug
            )
            return self._call_chat(
                prompt_messages,
                TOOLS,
                min(MINIMAL_CONTEXT_MAX_TOKENS, available_tokens)
            )
    
    def run(self) -> CommitResponse:
        """Run the agent to find the fix commit for a CVE.
        
        Returns:
            A CommitResponse (either success or error) containing the CVE 
            information and fix commit, or error details if not found.
        """
        self._initialize_messages()

        for step in range(1, max(1, self.steps) + 1):
            if self.debug:
                print(f"[step {step}] chat | model={self.model_name}")

            self._check_finalization_condition()

            prompt_messages, available_tokens = build_prompt_that_fits(
                self.messages, debug=self.debug
            )
            max_tokens = max(1, available_tokens)

            try:
                response = self._call_chat_with_fallback(prompt_messages, max_tokens)
            except Exception as hard_exc:
                if self.debug:
                    print(f"[chat hard fail] {hard_exc}")
                return self._create_error_response(
                    "Model/server refused due to context limits"
                )

            message = response.choices[0].message

            if getattr(message, "tool_calls", None):
                self._handle_tool_calls(message)
                continue

            content = message.content or ""
            if self.debug:
                print(f"[assistant] {content[:4000]}\n")
            try:
                return json.loads(content)
            except Exception:
                self.messages.append({"role": MESSAGE_ROLE_ASSISTANT, "content": content[:2000]})
                self.messages.append({
                    "role": MESSAGE_ROLE_USER,
                    "content": "Respond now as STRICT JSON only. Do not call tools."
                })
                continue

        return self._create_error_response(
            "Reached max steps without a valid JSON answer"
        )


def run_agent(
    cve_id: str,
    model: Optional[str],
    base_url: Optional[str],
    steps: int,
    debug: bool
) -> CommitResponse:
    """Run the agent to find the fix commit for a CVE.
    
    This is a convenience function that creates a PatchFinderAgent instance
    and runs it.
    
    Args:
        cve_id: The CVE identifier (e.g., 'CVE-2025-0762').
        model: The model name to use, or None for default.
        base_url: The API base URL, or None for default.
        steps: Maximum number of interaction rounds.
        debug: Whether to print debug information.
        
    Returns:
        A CommitResponse (either success or error) containing the CVE
        information and fix commit, or error details if not found.
    """
    agent = PatchFinderAgent(cve_id, model, base_url, steps, debug)
    return agent.run()


__all__ = ["run_agent", "PatchFinderAgent", "CommitResponse", "CommitSuccessResponse", "CommitErrorResponse"]

