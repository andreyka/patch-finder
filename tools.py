"""Tool implementations and HTML helpers for the patch finder agent."""

from __future__ import annotations

import atexit
import contextlib
import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup, FeatureNotFound

try:  # pragma: no cover - optional dependency at runtime
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, sync_playwright

    _PLAYWRIGHT_AVAILABLE = True
except ImportError:  # pragma: no cover - handled at runtime
    PlaywrightTimeoutError = Exception
    sync_playwright = None  # type: ignore[assignment]
    _PLAYWRIGHT_AVAILABLE = False

if TYPE_CHECKING:  # pragma: no cover - type-only imports
    from playwright.sync_api import Browser, BrowserContext, Page
else:
    Browser = BrowserContext = Page = Any

from config import (
    FETCH_TEXT_CAP,
    GITLAB_TOKEN,
    GOOGLE_API_KEY,
    GOOGLE_CSE_ID,
    HTTP_PROXIES,
    PLAYWRIGHT_ENABLED,
    PLAYWRIGHT_HEADLESS,
    PLAYWRIGHT_NAV_TIMEOUT,
    PLAYWRIGHT_PROXY,
    REQUEST_TIMEOUT,
    UA,
)

COMMIT_PATTERNS = [
    re.compile(r"https?://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{40})"),
    re.compile(r"https?://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})"),
    re.compile(r"https?://github\.com/([^/]+)/([^/]+)/pull/\\d+/commits/([0-9a-f]{7,40})"),
    re.compile(r"https?://git\.kernel\.org/[^ ]*?/commit/\\?id=([0-9a-f]{7,40})"),
    re.compile(r"https?://git\.openssl\.org/[^ ]*?;a=commit;h=([0-9a-f]{7,40})"),
    re.compile(r"https?://[^/]*\.googlesource\.com/[^/]+/\+/([0-9a-f]{40})"),
    re.compile(r"https?://[^/]*\.googlesource\.com/[^/]+/\+/([0-9a-f]{7,40})"),
]

_playwright_ctx = None
_browser: Optional[Browser] = None
_browser_context: Optional[BrowserContext] = None
_playwright_registered = False


def _shutdown_playwright() -> None:
    """Close Playwright resources to avoid orphaned browser processes."""
    global _browser_context, _browser, _playwright_ctx
    with contextlib.suppress(Exception):
        if _browser_context is not None:
            _browser_context.close()
    with contextlib.suppress(Exception):
        if _browser is not None:
            _browser.close()
    with contextlib.suppress(Exception):
        if _playwright_ctx is not None:
            _playwright_ctx.stop()
    _browser_context = None
    _browser = None
    _playwright_ctx = None


def _ensure_browser_context() -> BrowserContext:
    """Create or reuse a shared Playwright browser context."""
    global _browser_context, _browser, _playwright_ctx, _playwright_registered
    if not PLAYWRIGHT_ENABLED:
        raise RuntimeError("Playwright support disabled by configuration")
    if not _PLAYWRIGHT_AVAILABLE:
        raise RuntimeError("Playwright is not installed; run 'pip install playwright'")
    if _browser_context is not None:
        return _browser_context

    if sync_playwright is None:
        raise RuntimeError("Playwright import failed")

    _playwright_ctx = sync_playwright().start()
    launch_args = {"headless": PLAYWRIGHT_HEADLESS}
    if PLAYWRIGHT_PROXY:
        launch_args["proxy"] = {"server": PLAYWRIGHT_PROXY}
    _browser = _playwright_ctx.chromium.launch(**launch_args)
    _browser_context = _browser.new_context(user_agent=UA, ignore_https_errors=True)
    if not _playwright_registered:
        atexit.register(_shutdown_playwright)
        _playwright_registered = True
    return _browser_context


def _fetch_with_playwright(url: str, debug: bool = False) -> Tuple[str, str]:
    """Fetch a URL with Playwright and return HTML content and final URL."""
    context = _ensure_browser_context()
    page: Optional[Page] = None
    try:
        page = context.new_page()
        extra_headers = {"User-Agent": UA}
        if GITLAB_TOKEN and ("gitlab.com" in url.lower() or "gitlab." in url.lower()):
            extra_headers["PRIVATE-TOKEN"] = GITLAB_TOKEN
        page.set_extra_http_headers(extra_headers)
        timeout_ms = max(1, PLAYWRIGHT_NAV_TIMEOUT) * 1000
        try:
            page.goto(url, wait_until="networkidle", timeout=timeout_ms)
        except PlaywrightTimeoutError:
            if debug:
                print(f"[tool:fetch_url] Playwright navigation timeout for {url}")
            page.wait_for_timeout(500)
        html = page.content()
        final_url = page.url
        return html, final_url
    finally:
        if page is not None:
            with contextlib.suppress(Exception):
                page.close()


def _fetch_with_requests(url: str, debug: bool = False) -> Tuple[str, str]:
    """Fetch a URL with requests and return HTML content and final URL."""
    headers = {"User-Agent": UA}
    if GITLAB_TOKEN and ("gitlab.com" in url.lower() or "gitlab." in url.lower()):
        headers["PRIVATE-TOKEN"] = GITLAB_TOKEN
        if debug:
            print("[tool:fetch_url] Using GitLab token for authentication")
    response = requests.get(
        url,
        headers=headers,
        proxies=HTTP_PROXIES,
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return response.text, response.url


def _soup(html: str) -> BeautifulSoup:
    """Create a BeautifulSoup object with the best available parser.
    
    Args:
        html: The HTML string to parse.
        
    Returns:
        A BeautifulSoup object.
    """
    try:
        return BeautifulSoup(html, "lxml")
    except FeatureNotFound:  # pragma: no cover - environment dependent
        return BeautifulSoup(html, "html.parser")


def _soup_title_and_canonical(
    soup: BeautifulSoup,
    url: str
) -> Tuple[str, str]:
    """Extract the title and canonical URL from a parsed HTML page.
    
    Args:
        soup: The BeautifulSoup object representing the page.
        url: The original URL of the page.
        
    Returns:
        A tuple of (title, canonical_url).
    """
    canonical = ""
    link_canon = soup.find(
        "link",
        rel=lambda v: v and "canonical" in v.lower()
    )
    if link_canon and link_canon.get("href"):
        canonical = urljoin(url, link_canon["href"].strip())
    og_title = soup.find("meta", property="og:title")
    if og_title and og_title.get("content"):
        title = og_title["content"].strip()
    elif soup.title and soup.title.string:
        title = soup.title.string.strip()
    else:
        title = url.rsplit("/", 1)[-1] or url
    return title, (canonical or url)


def _soup_visible_text(soup: BeautifulSoup) -> str:
    """Extract visible text from a BeautifulSoup object.
    
    Removes script, style, navigation, and other non-content elements
    before extracting text.
    
    Args:
        soup: The BeautifulSoup object to extract text from.
        
    Returns:
        The cleaned, visible text content.
    """
    for tag in ("script", "style", "noscript", "template", "svg", "math"):
        for element in soup.find_all(tag):
            element.decompose()
    for sel in ("nav", "footer", "header", "iframe"):
        for element in soup.find_all(sel):
            element.decompose()
    text = soup.get_text(" ", strip=True)
    return re.sub(r"\\s+", " ", text).strip()


def extract_commit_links(text_or_html: str) -> List[str]:
    """Extract commit URLs from text or HTML content.
    
    Searches for commit links from GitHub, git.kernel.org, git.openssl.org,
    and other common Git hosting services.
    
    Args:
        text_or_html: The text or HTML content to search.
        
    Returns:
        A list of unique commit URLs found in the content.
    """
    out: List[str] = []
    seen: set[str] = set()
    for pat in COMMIT_PATTERNS:
        for match in pat.finditer(text_or_html):
            url = match.group(0)
            if "git.openssl.org" in url:
                sha = match.group(1)
                url = (
                    f"https://git.openssl.org/gitweb/"
                    f"?p=openssl.git;a=commit;h={sha}"
                )
            if url not in seen:
                seen.add(url)
                out.append(url)
    return out


def extract_commit_links_from_soup(
    soup: BeautifulSoup,
    base_url: str
) -> List[str]:
    """Extract commit URLs from anchor tags in a BeautifulSoup object.
    
    Args:
        soup: The BeautifulSoup object to search.
        base_url: The base URL for resolving relative links.
        
    Returns:
        A sorted list of unique commit URLs found in the page.
    """
    links: set[str] = set()
    for anchor in soup.find_all("a", href=True):
        href = urljoin(base_url, anchor["href"])
        for pat in COMMIT_PATTERNS:
            if pat.search(href):
                if "git.openssl.org" in href:
                    match = re.search(
                        r";a=commit;h=([0-9a-f]{7,40})",
                        href
                    )
                    if match:
                        sha = match.group(1)
                        href = (
                            f"https://git.openssl.org/gitweb/"
                            f"?p=openssl.git;a=commit;h={sha}"
                        )
                links.add(href)
    return sorted(links)


def tool_web_search(query: str, debug: bool = False) -> str:
    """Perform a Google Custom Search and return formatted results.
    
    Args:
        query: The search query string.
        debug: Whether to print debug information.
        
    Returns:
        A formatted string with search results, or an error message.
    """
    if not GOOGLE_API_KEY or not GOOGLE_CSE_ID:
        return (
            "ERROR: Google Search not configured "
            "(set GOOGLE_API_KEY and GOOGLE_CSE_ID)."
        )
    if debug:
        print(f"[tool:web_search] {query}")
    try:
        params = {"key": GOOGLE_API_KEY, "cx": GOOGLE_CSE_ID, "q": query, "num": 10}
        response = requests.get(
            "https://www.googleapis.com/customsearch/v1",
            params=params,
            proxies=HTTP_PROXIES,
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code != 200:
            return f"ERROR: Google CSE HTTP {response.status_code}: {response.text[:400]}"
        items = (response.json().get("items") or [])[:10]
        if not items:
            return "No results."
        lines: List[str] = []
        for idx, item in enumerate(items, start=1):
            title = (item.get("title") or "").strip()
            link = item.get("link") or ""
            snippet = (item.get("snippet") or "").strip()
            lines.append(f"{idx}. {title}\n{link}")
            if snippet:
                lines.append(f"Snippet: {snippet}")
            lines.append("")
        return "\n".join(lines).strip()
    except Exception as exc:  # pragma: no cover - network runtime
        return f"ERROR: web_search exception: {exc}"


def tool_fetch_url(url: str, debug: bool = False) -> str:
    """Fetch a URL and return extracted text with commit references.
    
    Args:
        url: The URL to fetch.
        debug: Whether to print debug information.
        
    Returns:
        A formatted string with the page title, URL, commit references,
        and visible text content, or an error message.
    """
    if debug:
        print(f"[tool:fetch_url] {url}")
    html = ""
    final_url = url
    errors: List[str] = []
    source = ""

    if PLAYWRIGHT_ENABLED:
        try:
            html, final_url = _fetch_with_playwright(url, debug=debug)
            source = "playwright"
            if not html.strip():
                html = ""
        except Exception as exc:  # pragma: no cover - runtime safety
            errors.append(f"Playwright error: {exc}")
            if debug:
                print(f"[tool:fetch_url] Playwright failed for {url}: {exc}")

    if not html:
        try:
            html, final_url = _fetch_with_requests(url, debug=debug)
            source = source or "requests"
        except Exception as exc:  # pragma: no cover - network runtime
            if errors:
                return f"ERROR: fetch_url exception: {exc} | {'; '.join(errors)}"
            return f"ERROR: fetch_url exception: {exc}"

    if debug and source:
        print(f"[tool:fetch_url] Source: {source}")
    if debug and errors:
        for err in errors:
            print(f"[tool:fetch_url] {err}")

    soup = _soup(html)
    title, canonical = _soup_title_and_canonical(soup, final_url)
    commits = extract_commit_links_from_soup(soup, final_url)

    text = _soup_visible_text(soup)
    if len(text) > FETCH_TEXT_CAP:
        text = text[:FETCH_TEXT_CAP] + " ...[truncated]"

    lines = [f"Title: {title}", f"URL: {canonical}", ""]
    if commits:
        lines.append("Possible commit references:")
        lines.extend(commits)
        lines.append("")
    lines.append("Page text:")
    lines.append(text)
    return "\n".join(lines).strip()


TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Google search for CVE/advisory/commit info; returns titles, links, snippets.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_url",
            "description": "Fetch a web page and return large plain text + any commit links found.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
]


__all__ = [
    "COMMIT_PATTERNS",
    "TOOLS",
    "extract_commit_links",
    "extract_commit_links_from_soup",
    "tool_fetch_url",
    "tool_web_search",
]








