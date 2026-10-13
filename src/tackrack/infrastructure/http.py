"""Bounded, read-only transport for the explicitly approved public GitHub API.

Production clients verify TLS, ignore proxy/credential environment variables, and
never follow redirects. Injected clients are a trusted test seam (MockTransport),
not a way to authorize additional origins or client-side credentials.
"""

from __future__ import annotations

import json
from contextlib import closing
from dataclasses import dataclass
from time import monotonic
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx

from tackrack.infrastructure.redaction import sanitize, sensitive_key

API_ORIGIN = "https://api.github.com"
# Currently supported, published version; see https://docs.github.com/en/rest/about-the-rest-api/api-versions.
API_VERSION = "2026-03-10"
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_ATTEMPTS = 3
TIMEOUT = httpx.Timeout(10.0, connect=5.0)
OPERATION_SECONDS = 120.0
CoverageStatus = Literal[
    "complete",
    "partial",
    "not_inspected",
    "permission_denied",
    "unsupported",
    "unavailable",
    "rate_limited",
    "error",
]


class HTTPFailure(Exception):
    """Deliberately contains no server text, credentials, or request URL."""

    def __init__(self, status: CoverageStatus, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


@dataclass(frozen=True)
class JSONResponse:
    data: Any
    body_digest: str
    next_url: str | None


def approved_url(url: str) -> httpx.URL:
    """Only exact HTTPS api.github.com, without userinfo or fragments."""
    try:
        parts = urlsplit(url)
        if (
            parts.scheme != "https"
            or parts.netloc not in {"api.github.com", "api.github.com:443"}
            or parts.fragment
            or not parts.path.startswith("/repos/")
            or any(ord(char) < 33 for char in url)
            or "\\" in url
            or "%" in parts.path
            or any(segment in {".", ".."} for segment in parts.path.split("/"))
        ):
            raise ValueError
        return httpx.URL(url)
    except (ValueError, httpx.InvalidURL):
        raise HTTPFailure("error", "unapproved API URL") from None


class GitHubHTTP:
    """GET-only JSON transport; limits apply even to an injected HTTPX client."""

    def __init__(self, client: httpx.Client | None, token: str | None) -> None:
        self._owns_client = client is None
        self._deadline = monotonic() + OPERATION_SECONDS
        self._token = token
        self._client = (
            client
            if client is not None
            else httpx.Client(verify=True, trust_env=False, timeout=TIMEOUT, follow_redirects=False)
        )
        self._headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "TackRack/0.1.0",
        }
        if token:
            self._headers["Authorization"] = f"Bearer {token}"

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def get(self, url: str) -> JSONResponse:
        from hashlib import sha256

        approved = approved_url(url)
        for attempt in range(MAX_ATTEMPTS):
            remaining = self._deadline - monotonic()
            if remaining <= 0:
                raise HTTPFailure("partial", "API operation deadline")
            timeout = httpx.Timeout(min(10.0, remaining), connect=min(5.0, remaining))
            request = httpx.Request(
                "GET",
                approved,
                headers=self._headers,
                extensions={"timeout": timeout.as_dict()},
            )
            try:
                response = self._client.send(
                    request, stream=True, auth=None, follow_redirects=False
                )
                with closing(response):
                    status = response.status_code
                    if status == 429 or (
                        status == 403
                        and (
                            response.headers.get("x-ratelimit-remaining") == "0"
                            or "retry-after" in response.headers
                        )
                    ):
                        raise HTTPFailure("rate_limited", "GitHub API rate limit")
                    if status in {401, 403}:
                        raise HTTPFailure("permission_denied", "GitHub API access denied")
                    if status == 404:
                        raise HTTPFailure("unavailable", "resource absent or not visible")
                    if 300 <= status < 400:
                        raise HTTPFailure("error", "API redirect refused")
                    if status in {502, 503, 504} and attempt + 1 < MAX_ATTEMPTS:
                        continue
                    if status != 200:
                        raise HTTPFailure("error", f"GitHub API HTTP {status}")
                    length = response.headers.get("content-length", "")
                    if length.isdecimal() and int(length) > MAX_BODY_BYTES:
                        raise HTTPFailure("partial", "API response body limit")
                    body = bytearray()
                    for chunk in response.iter_bytes(chunk_size=16384):
                        if monotonic() >= self._deadline:
                            raise HTTPFailure("partial", "API operation deadline")
                        if len(body) + len(chunk) > MAX_BODY_BYTES:
                            raise HTTPFailure("partial", "API response body limit")
                        body.extend(chunk)
                    try:
                        data = json.loads(
                            body, parse_constant=_reject_constant, object_pairs_hook=_unique_object
                        )
                    except (ValueError, UnicodeError, RecursionError):
                        raise HTTPFailure("error", "invalid API JSON") from None
                    next_url = _next_link(response)
                    if next_url is not None:
                        candidate = approved_url(next_url)
                        if candidate.path != approved.path:
                            raise HTTPFailure("error", "pagination changed API endpoint")
                    sensitive = _sensitive_json(data, self._token)
                    identity = (
                        "withheld-sensitive-response" if sensitive else sha256(body).hexdigest()
                    )
                    return JSONResponse(data, identity, next_url)
            except httpx.HTTPError:
                if attempt + 1 == MAX_ATTEMPTS:
                    raise HTTPFailure(
                        "error", "API transport failed after bounded retries"
                    ) from None
        raise HTTPFailure("error", "API retry limit")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate API JSON key")
        value[key] = item
    return value


def _sensitive_json(value: Any, token: str | None, depth: int = 0) -> bool:
    if depth > 12:
        return True
    if isinstance(value, dict):
        return len(value) > 1000 or any(
            sensitive_key(key) or _sensitive_json(item, token, depth + 1)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return len(value) > 1000 or any(_sensitive_json(item, token, depth + 1) for item in value)
    return isinstance(value, str) and (bool(token and token in value) or sanitize(value)[1])


def _reject_constant(value: str) -> None:
    raise ValueError("non-finite JSON")


def _next_link(response: httpx.Response) -> str | None:
    # HTTPX parses RFC-style Link headers; never follow URLs found in JSON bodies.
    link = response.links.get("next")
    if link is None:
        return None
    url = link.get("url")
    if not isinstance(url, str) or len(url) > 4096:
        raise HTTPFailure("error", "invalid API pagination")
    return url
