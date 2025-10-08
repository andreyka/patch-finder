"""Configuration helpers for the new high-context agent."""

from __future__ import annotations

import os
from typing import Dict


def _env_flag(name: str, default: bool = True) -> bool:
    """Parse a boolean flag from an environment variable.
    
    Args:
        name: The environment variable name.
        default: The default value if not set.
        
    Returns:
        The boolean value of the environment variable.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no"}


UA = os.environ.get("PATCH_FINDER_USER_AGENT", "patch-finder/4.2 (+https://example.local)")

GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "").strip()
GOOGLE_CSE_ID = os.environ.get("GOOGLE_CSE_ID", "").strip()

GITLAB_TOKEN = os.environ.get("GITLAB_TOKEN", "").strip()

HTTP_PROXIES: Dict[str, str] = {}
if proxy := os.environ.get("HTTP_PROXY"):
    HTTP_PROXIES["http"] = proxy
if proxy := os.environ.get("HTTPS_PROXY"):
    HTTP_PROXIES["https"] = proxy

MAX_MODEL_LEN = int(os.environ.get("MAX_MODEL_LEN", "131072"))
MIN_COMPLETION_TOKENS = int(os.environ.get("MIN_COMPLETION_TOKENS", "256"))
COMPLETION_CAP = int(os.environ.get("COMPLETION_CAP", "4096"))
SAFETY_TOKENS = int(os.environ.get("SAFETY_TOKENS", "1024"))
FETCH_TEXT_CAP = int(os.environ.get("FETCH_TEXT_CAP", "80000"))
MAX_TOOL_MSGS = int(os.environ.get("MAX_TOOL_MSGS", "80"))
TOOL_TRUNC_TOK = int(os.environ.get("TOOL_TRUNC_TOK", "15000"))
NO_PROGRESS_WINDOW = int(os.environ.get("NO_PROGRESS_WINDOW", "4"))
NO_PROGRESS_PATIENCE = int(os.environ.get("NO_PROGRESS_PATIENCE", "2"))
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "30"))
BOOTSTRAP = _env_flag("BOOTSTRAP", True)
BOOTSTRAP_SECTION_TOK_CAP = int(os.environ.get("BOOTSTRAP_SECTION_TOK_CAP", "10000"))
AUTO_EXPAND_COMMITS = _env_flag("AUTO_EXPAND_COMMITS", True)
COMMIT_EXPAND_LIMIT = int(os.environ.get("COMMIT_EXPAND_LIMIT", "4"))
TOOL_CALL_DELAY_SEC = float(os.environ.get("TOOL_CALL_DELAY_SEC", "0.08"))
DEFAULT_MODEL = os.environ.get("OPENAI_MODEL", "openai/gpt-oss-20b")
DEFAULT_BASE_URL = os.environ.get("OPENAI_BASE_URL")


__all__ = [
    "UA",
    "GOOGLE_API_KEY",
    "GOOGLE_CSE_ID",
    "HTTP_PROXIES",
    "MAX_MODEL_LEN",
    "MIN_COMPLETION_TOKENS",
    "COMPLETION_CAP",
    "SAFETY_TOKENS",
    "FETCH_TEXT_CAP",
    "MAX_TOOL_MSGS",
    "TOOL_TRUNC_TOK",
    "NO_PROGRESS_WINDOW",
    "NO_PROGRESS_PATIENCE",
    "REQUEST_TIMEOUT",
    "BOOTSTRAP",
    "BOOTSTRAP_SECTION_TOK_CAP",
    "AUTO_EXPAND_COMMITS",
    "COMMIT_EXPAND_LIMIT",
    "TOOL_CALL_DELAY_SEC",
    "DEFAULT_MODEL",
    "DEFAULT_BASE_URL",
]
