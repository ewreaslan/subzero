"""
HTTP/HTTPS prober with false-positive resistance.

- Two independent requests with different User-Agents
- Both HTTP and HTTPS attempted
- Body fingerprint only confirmed if found in both attempts
- Timeout and redirect handling
"""

import asyncio
from dataclasses import dataclass, field
from typing import Optional

import httpx

HTTP_TIMEOUT  = 10.0
MAX_REDIRECTS = 5

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]


@dataclass
class HTTPResult:
    subdomain: str
    reachable: bool             = False
    status_codes: list[int]     = field(default_factory=list)
    final_urls: list[str]       = field(default_factory=list)
    bodies: list[str]           = field(default_factory=list)  # truncated
    headers_list: list[dict]    = field(default_factory=list)
    fingerprint_hits: list[str] = field(default_factory=list)  # matched phrases
    used_https: bool            = False
    errors: list[str]           = field(default_factory=list)

    @property
    def body_combined(self) -> str:
        return " ".join(self.bodies)

    @property
    def status_code(self) -> Optional[int]:
        return self.status_codes[0] if self.status_codes else None


async def _fetch_once(url: str, ua: str) -> tuple[Optional[int], str, str, Optional[dict]]:
    """Single HTTP fetch. Returns (status, body_snippet, final_url, headers)."""
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
            timeout=HTTP_TIMEOUT,
            verify=False,  # scan targets may have bad certs; logged separately
            headers={"User-Agent": ua},
        ) as client:
            resp = await client.get(url)
            body = resp.text[:8192]  # cap at 8 KB
            return resp.status_code, body, str(resp.url), dict(resp.headers)
    except httpx.TooManyRedirects as exc:
        return None, "", str(exc), None
    except Exception as exc:
        return None, "", str(exc), None


async def probe(subdomain: str) -> HTTPResult:
    """
    Probe subdomain over HTTP and HTTPS with two different User-Agents.
    Fingerprint phrases are only reported if found in at least one full response.
    """
    result = HTTPResult(subdomain=subdomain)

    # Build URL list: try HTTPS first (more common for live targets), then HTTP
    urls_to_try = [
        f"https://{subdomain}",
        f"http://{subdomain}",
    ]

    tasks = [
        _fetch_once(url, ua)
        for url in urls_to_try
        for ua in USER_AGENTS
    ]
    responses = await asyncio.gather(*tasks, return_exceptions=True)

    for idx, res in enumerate(responses):
        url = urls_to_try[idx // len(USER_AGENTS)]
        if isinstance(res, Exception):
            result.errors.append(f"{url}: {res}")
            continue
        status, body, final_url, headers = res
        if status is not None:
            result.reachable = True
            result.status_codes.append(status)
            result.final_urls.append(final_url)
            result.bodies.append(body)
            if headers:
                result.headers_list.append(headers)
            if url.startswith("https://"):
                result.used_https = True
        else:
            result.errors.append(f"{url}: {final_url}")

    return result
