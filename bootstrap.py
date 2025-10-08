"""Bootstrap evidence assembly for the new agent."""

from __future__ import annotations

import re
from typing import List, Optional, Set, Tuple

try:
    from .config import BOOTSTRAP_SECTION_TOK_CAP, COMMIT_EXPAND_LIMIT
    from .tools import extract_commit_links, tool_fetch_url, tool_web_search
    from .tokenizer import truncate_to_token_cap
except ImportError:  # pragma: no cover - script execution fallback
    from config import BOOTSTRAP_SECTION_TOK_CAP, COMMIT_EXPAND_LIMIT
    from tools import extract_commit_links, tool_fetch_url, tool_web_search
    from tokenizer import truncate_to_token_cap


class EvidenceBootstrap:
    """Bootstrap evidence collection for CVE research."""
    
    def __init__(self, debug: bool = False):
        """Initialize the evidence bootstrapper.
        
        Args:
            debug: Whether to print debug information.
        """
        self.debug = debug
        self.sections: List[str] = []
    
    def _add_section(self, title: str, body: str) -> None:
        """Add a section to the evidence collection.
        
        Args:
            title: The section title.
            body: The section content.
        """
        trimmed = truncate_to_token_cap(body, BOOTSTRAP_SECTION_TOK_CAP)
        self.sections.append(f"### {title}\n{trimmed}\n")
    
    def _fetch_primary_sources(self, cve_id: str) -> Tuple[str, str]:
        """Fetch NVD and CVE.org content.
        
        Args:
            cve_id: The CVE identifier.
            
        Returns:
            A tuple of (nvd_content, cve_content).
        """
        nvd_content = tool_fetch_url(
            f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            debug=self.debug
        )
        cve_content = tool_fetch_url(
            f"https://www.cve.org/CVERecord?id={cve_id}",
            debug=self.debug
        )
        return nvd_content, cve_content
    
    def _extract_chromium_bugs(self, content: str) -> Set[str]:
        """Extract Chromium bug IDs from content.
        
        Args:
            content: The content to search for bug IDs.
            
        Returns:
            A set of Chromium bug IDs found.
        """
        chromium_bug_ids: Set[str] = set()
        
        # Extract bug IDs from various formats
        patterns = [
            r"crbug\.com/(\d+)",
            r"bugs\.chromium\.org/p/chromium/issues/detail\?id=(\d+)",
            r"issues\.chromium\.org/issues/(\d+)",
            r"Issue (\d{6,})",
            r"Bug (\d{6,})",
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                bug_id = match.group(1)
                chromium_bug_ids.add(bug_id)
        
        return chromium_bug_ids
    
    def _fetch_ghsa_advisory(self, cve_id: str) -> Optional[str]:
        """Search and fetch GHSA advisory if available.
        
        Args:
            cve_id: The CVE identifier.
            
        Returns:
            The GHSA advisory URL if found, None otherwise.
        """
        ghsa_block = tool_web_search(
            f'site:github.com/advisories "{cve_id}"',
            debug=self.debug
        )
        self._add_section("GHSA search", ghsa_block)
        
        pattern = (
            r"https://github\.com/(?:advisories|"
            r"[^/]+/[^/]+/security/advisories)/[^\s)]+"
        )
        for match in re.finditer(pattern, ghsa_block or ""):
            return match.group(0)
        
        return None
    
    def _fetch_chromium_commits(self, bug_ids: Set[str]) -> None:
        """Fetch Chromium commit information for bug IDs.
        
        Args:
            bug_ids: Set of Chromium bug IDs to search for.
        """
        if not bug_ids:
            return
        
        if self.debug:
            print(f"[bootstrap] Found Chromium bug IDs: {bug_ids}")
        
        # Search for commits related to the first bug ID
        bug_id = sorted(bug_ids)[0]
        chromium_commit_search = tool_web_search(
            f'site:chromium.googlesource.com "{bug_id}" commit',
            debug=self.debug
        )
        self._add_section("Chromium commit search", chromium_commit_search)
    
    def _build_url_list(
        self,
        cve_id: str,
        chromium_bug_ids: Set[str],
        ghsa_link: Optional[str]
    ) -> List[Tuple[str, str]]:
        """Build the list of URLs to fetch.
        
        Args:
            cve_id: The CVE identifier.
            chromium_bug_ids: Set of Chromium bug IDs found.
            ghsa_link: GHSA advisory URL if found.
            
        Returns:
            List of (title, url) tuples to fetch.
        """
        urls = [
            (f"NVD {cve_id}", f"https://nvd.nist.gov/vuln/detail/{cve_id}"),
            (f"CVE.org {cve_id}", f"https://www.cve.org/CVERecord?id={cve_id}"),
            (f"OSV API {cve_id}", f"https://api.osv.dev/v1/vulns/{cve_id}"),
            (f"OSV page {cve_id}", f"https://osv.dev/vulnerability/{cve_id}"),
            (f"Debian {cve_id}", f"https://security-tracker.debian.org/tracker/{cve_id}"),
        ]
        
        # Add Chromium bug URLs at the beginning if found
        if chromium_bug_ids:
            for bug_id in sorted(chromium_bug_ids)[:3]:
                bug_url = f"https://issues.chromium.org/issues/{bug_id}"
                urls.insert(0, (f"Chromium bug {bug_id}", bug_url))
        
        # Add GHSA advisory at the beginning if found
        if ghsa_link:
            urls.insert(0, ("GHSA advisory", ghsa_link))
        
        return urls
    
    def _expand_commits(self, aggregate: str) -> None:
        """Extract and fetch commit URLs from aggregated content.
        
        Args:
            aggregate: The aggregated content to search for commits.
        """
        commit_urls = extract_commit_links(aggregate)[:COMMIT_EXPAND_LIMIT]
        if not commit_urls:
            return
        
        expanded: List[str] = []
        for commit_url in commit_urls:
            expanded.append(tool_fetch_url(commit_url, debug=self.debug))
        
        self._add_section("Expanded commit pages", "\n\n".join(expanded))
    
    def bootstrap(self, cve_id: str) -> str:
        """Prefetch high-signal sources to shorten the LLM search loop.
        
        Fetches CVE information from multiple authoritative sources including
        NVD, CVE.org, OSV, GHSA, and Debian tracker, then expands any
        commit URLs found.
        
        Args:
            cve_id: The CVE identifier to research.
            
        Returns:
            A formatted string containing evidence from all sources.
        """
        self.sections = []  # Reset sections for new bootstrap
        
        # Fetch primary sources to extract references
        nvd_content, cve_content = self._fetch_primary_sources(cve_id)
        
        # Extract Chromium bug IDs if present
        combined_content = nvd_content + " " + cve_content
        chromium_bug_ids = self._extract_chromium_bugs(combined_content)
        
        # Search for GHSA advisory
        ghsa_link = self._fetch_ghsa_advisory(cve_id)
        
        # Search for Chromium commits if we found bug IDs
        if chromium_bug_ids:
            self._fetch_chromium_commits(chromium_bug_ids)
        
        # Build and fetch all URLs
        urls = self._build_url_list(cve_id, chromium_bug_ids, ghsa_link)
        for title, url in urls:
            fetched = tool_fetch_url(url, debug=self.debug)
            self._add_section(title, fetched)
        
        # Expand any commit URLs found in the aggregated content
        aggregate = "\n".join(self.sections)
        self._expand_commits(aggregate)
        
        return (
            "BOOTSTRAP EVIDENCE (pre-fetched for you to analyze quickly):\n\n" +
            "\n".join(self.sections)
        )


def bootstrap_evidence(cve_id: str, debug: bool = False) -> str:
    """Prefetch high-signal sources to shorten the LLM search loop.
    
    This is a convenience function that creates an EvidenceBootstrap instance
    and runs it.
    
    Fetches CVE information from multiple authoritative sources including
    NVD, CVE.org, OSV, GHSA, and Debian tracker, then expands any
    commit URLs found.
    
    Args:
        cve_id: The CVE identifier to research.
        debug: Whether to print debug information.
        
    Returns:
        A formatted string containing evidence from all sources.
    """
    bootstrapper = EvidenceBootstrap(debug=debug)
    return bootstrapper.bootstrap(cve_id)


__all__ = ["bootstrap_evidence", "EvidenceBootstrap"]

