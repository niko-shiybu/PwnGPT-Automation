from __future__ import annotations

import json
import os
import time
from abc import ABC, abstractmethod
from typing import List
from urllib.parse import quote

from retrieve.schemas import SearchQuery, SearchResult


class SearchClient(ABC):
    @abstractmethod
    def search(self, query: SearchQuery, *, max_results: int = 5) -> List[SearchResult]:
        ...

    @property
    @abstractmethod
    def available(self) -> bool:
        ...


class DummySearchClient(SearchClient):
    """Returns empty results when no API key is configured."""

    def search(self, query: SearchQuery, *, max_results: int = 5) -> List[SearchResult]:
        return []

    @property
    def available(self) -> bool:
        return False


class BraveSearchClient(SearchClient):
    """Brave Search API client."""

    def __init__(self, api_key: str = ""):
        self._api_key = api_key or os.environ.get("BRAVE_SEARCH_API_KEY", "")
        self._base_url = "https://api.search.brave.com/res/v1/web/search"

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    def search(self, query: SearchQuery, *, max_results: int = 5) -> List[SearchResult]:
        if not self._api_key:
            return []

        import urllib.request

        params = {
            "q": query.query,
            "count": str(min(max_results, 10)),
        }
        url = self._base_url + "?" + "&".join(f"{k}={quote(str(v))}" for k, v in params.items())

        req = urllib.request.Request(url)
        req.add_header("Accept", "application/json")
        req.add_header("X-Subscription-Token", self._api_key)

        try:
            import gzip
            resp = urllib.request.urlopen(req, timeout=10)
            raw = resp.read()
            if resp.headers.get("Content-Encoding") == "gzip":
                raw = gzip.decompress(raw)
            data = json.loads(raw.decode("utf-8"))

            results: List[SearchResult] = []
            web_results = data.get("web", {}).get("results", [])
            for r in web_results[:max_results]:
                results.append(SearchResult(
                    title=r.get("title", ""),
                    url=r.get("url", ""),
                    snippet=r.get("description", ""),
                    source="brave",
                    query=query.query,
                ))
            return results
        except Exception:
            return []


class SerpApiSearchClient(SearchClient):
    """SerpAPI client (Google search API)."""

    def __init__(self, api_key: str = ""):
        self._api_key = api_key or os.environ.get("SERPAPI_API_KEY", "")
        self._base_url = "https://serpapi.com/search.json"

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    def search(self, query: SearchQuery, *, max_results: int = 5) -> List[SearchResult]:
        if not self._api_key:
            return []

        import urllib.request

        params = {
            "q": query.query,
            "api_key": self._api_key,
            "engine": "google",
            "num": str(min(max_results, 10)),
        }
        url = self._base_url + "?" + "&".join(f"{k}={quote(str(v))}" for k, v in params.items())

        try:
            resp = urllib.request.urlopen(url, timeout=10)
            data = json.loads(resp.read().decode("utf-8"))

            results: List[SearchResult] = []
            for r in data.get("organic_results", [])[:max_results]:
                results.append(SearchResult(
                    title=r.get("title", ""),
                    url=r.get("link", ""),
                    snippet=r.get("snippet", ""),
                    source="serpapi",
                    query=query.query,
                ))
            return results
        except Exception:
            return []


def _get_config(key: str) -> str:
    """Read config from environment, with local_config.py fallback."""
    val = os.environ.get(key, "")
    if val:
        return val
    try:
        from automation import local_config
        return getattr(local_config, key, "")
    except Exception:
        return ""


def _create_client() -> SearchClient:
    """Create the appropriate search client from environment or local_config."""
    provider = _get_config("PWN_SEARCH_PROVIDER").lower()

    if provider == "brave":
        return BraveSearchClient(_get_config("BRAVE_SEARCH_API_KEY"))
    elif provider in ("serpapi", "serp"):
        return SerpApiSearchClient(_get_config("SERPAPI_API_KEY"))
    else:
        # Auto-detect: check which API key is available
        if _get_config("BRAVE_SEARCH_API_KEY"):
            return BraveSearchClient(_get_config("BRAVE_SEARCH_API_KEY"))
        if _get_config("SERPAPI_API_KEY"):
            return SerpApiSearchClient(_get_config("SERPAPI_API_KEY"))
        return DummySearchClient()
