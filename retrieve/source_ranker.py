from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse

from retrieve.schemas import SearchResult

DOMAIN_SCORES = {
    "docs.pwntools.com": 1.00,
    "pwntools.com": 0.95,
    "ropemporium.com": 0.90,
    "ctftime.org": 0.75,
    "github.com": 0.70,
    "cromulence.com": 0.65,
    "ir0nstone.gitlab.io": 0.65,
    "0xdf.gitlab.io": 0.65,
    "blog.perfect.blue": 0.65,
    "ctf-wiki.org": 0.65,
    "pwn.college": 0.65,
    "nightmare.0x90.org": 0.60,
    "exploit.education": 0.60,
}

PERSONAL_BLOG_DOMAINS = re.compile(
    r"\.blogspot\.|\.wordpress\.|medium\.com|dev\.to|hashnode|substack",
    re.IGNORECASE,
)

PERSONAL_BLOG_SCORE = 0.40
UNKNOWN_SCORE = 0.25


def _extract_domain(url: str) -> str:
    """Extract the hostname from a URL, stripping www prefix."""
    try:
        host = urlparse(url).hostname or ""
        if host.startswith("www."):
            host = host[4:]
        return host.lower()
    except Exception:
        return ""


def score_source(domain: str) -> float:
    """Score a domain's trustworthiness for pwn-related content."""
    domain_lower = domain.lower()

    for known, score in sorted(DOMAIN_SCORES.items(), key=lambda x: -len(x[0])):
        if known in domain_lower:
            return score

    if PERSONAL_BLOG_DOMAINS.search(domain_lower):
        return PERSONAL_BLOG_SCORE

    # Academic domains (.edu, .ac.*)
    if domain_lower.endswith(".edu") or re.match(r".+\.ac\.[a-z]{2,3}$", domain_lower):
        return 0.65

    return UNKNOWN_SCORE


def rank_results(results: List[SearchResult]) -> List[SearchResult]:
    """Assign source trust scores to search results and sort by score descending."""
    for r in results:
        domain = _extract_domain(r.url) if r.url else r.source
        r.source_score = score_source(domain)
    return sorted(results, key=lambda x: -x.source_score)
