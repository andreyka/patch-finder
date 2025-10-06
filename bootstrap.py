"""Bootstrap evidence assembly for the new agent."""

from __future__ import annotations

import re
from typing import Callable, List

try:
    from .config import BOOTSTRAP_SECTION_TOK_CAP, COMMIT_EXPAND_LIMIT
    from .tools import extract_commit_links, tool_fetch_url, tool_web_search
    from .tokenizer import truncate_to_token_cap
except ImportError:  # pragma: no cover - script execution fallback
    from config import BOOTSTRAP_SECTION_TOK_CAP, COMMIT_EXPAND_LIMIT
    from tools import extract_commit_links, tool_fetch_url, tool_web_search
    from tokenizer import truncate_to_token_cap


def bootstrap_evidence(cve_id: str, debug: bool = False) -> str:
    """Prefetch high-signal sources to shorten the LLM search loop.
    
    Fetches CVE information from multiple authoritative sources including
    NVD, CVE.org, OSV, GHSA, and Debian tracker, then expands any
    commit URLs found.
    
    Args:
        cve_id: The CVE identifier to research.
        debug: Whether to print debug information.
        
    Returns:
        A formatted string containing evidence from all sources.
    """
    sections: List[str] = []

    def add_section(title: str, body: str) -> None:
        """Add a section to the evidence collection.
        
        Args:
            title: The section title.
            body: The section content.
        """
        trimmed = truncate_to_token_cap(body, BOOTSTRAP_SECTION_TOK_CAP)
        sections.append(f"### {title}\n{trimmed}\n")

    urls = [
        (
            f"NVD {cve_id}",
            f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        ),
        (f"CVE.org {cve_id}", f"https://www.cve.org/CVERecord?id={cve_id}"),
        (f"OSV API {cve_id}", f"https://api.osv.dev/v1/vulns/{cve_id}"),
        (f"OSV page {cve_id}", f"https://osv.dev/vulnerability/{cve_id}"),
        (
            f"Debian {cve_id}",
            f"https://security-tracker.debian.org/tracker/{cve_id}"
        ),
    ]

    # First fetch NVD and CVE.org to extract potential bug references
    nvd_content = tool_fetch_url(
        f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        debug=debug
    )
    cve_content = tool_fetch_url(
        f"https://www.cve.org/CVERecord?id={cve_id}",
        debug=debug
    )
    
    # Look for Chromium bug IDs in the fetched content
    combined_content = nvd_content + " " + cve_content
    chromium_bug_ids = set()
    
    # Extract bug IDs from various formats
    for pattern in [
        r"crbug\.com/(\d+)",
        r"bugs\.chromium\.org/p/chromium/issues/detail\?id=(\d+)",
        r"issues\.chromium\.org/issues/(\d+)",
        r"Issue (\d{6,})",
        r"Bug (\d{6,})",
    ]:
        for match in re.finditer(pattern, combined_content, re.IGNORECASE):
            bug_id = match.group(1)
            chromium_bug_ids.add(bug_id)
    
    # If we found Chromium bug IDs, try to fetch them directly
    if chromium_bug_ids:
        if debug:
            print(f"[bootstrap] Found Chromium bug IDs: {chromium_bug_ids}")
        for bug_id in sorted(chromium_bug_ids)[:3]:
            bug_url = f"https://issues.chromium.org/issues/{bug_id}"
            urls.insert(0, (f"Chromium bug {bug_id}", bug_url))

    ghsa_block = tool_web_search(
        f'site:github.com/advisories "{cve_id}"',
        debug=debug
    )
    add_section("GHSA search", ghsa_block)
    ghsa_link = None
    pattern = (
        r"https://github\.com/(?:advisories|"
        r"[^/]+/[^/]+/security/advisories)/[^\s)]+"
    )
    for match in re.finditer(pattern, ghsa_block or ""):
        ghsa_link = match.group(0)
        break
    if ghsa_link:
        urls.insert(0, ("GHSA advisory", ghsa_link))

    # Add specific Chromium searches if bug IDs were found
    if chromium_bug_ids and len(chromium_bug_ids) > 0:
        bug_id = sorted(chromium_bug_ids)[0]
        chromium_commit_search = tool_web_search(
            f'site:chromium.googlesource.com "{bug_id}" commit',
            debug=debug
        )
        add_section("Chromium commit search", chromium_commit_search)

    for title, url in urls:
        fetched = tool_fetch_url(url, debug=debug)
        add_section(title, fetched)

    aggregate = "\n".join(sections)
    commit_urls = extract_commit_links(aggregate)[:COMMIT_EXPAND_LIMIT]
    if commit_urls:
        expanded: List[str] = []
        for commit_url in commit_urls:
            expanded.append(tool_fetch_url(commit_url, debug=debug))
        add_section("Expanded commit pages", "\n\n".join(expanded))

    return (
        "BOOTSTRAP EVIDENCE (pre-fetched for you to analyze quickly):\n\n" +
        "\n".join(sections)
    )


__all__ = ["bootstrap_evidence"]
