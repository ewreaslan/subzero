"""Provider-level ownership validation checks (best-effort)."""

from dataclasses import dataclass, field
from typing import Optional
import os

import httpx


@dataclass
class ProviderCheckResult:
    provider: str
    claimable: Optional[bool]
    confidence: int
    detail: str
    raw: dict = field(default_factory=dict)


async def _fetch(url: str, headers: dict | None = None) -> tuple[int | None, str]:
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
            r = await client.get(url, headers=headers or {})
            return r.status_code, r.text[:2048]
    except Exception as exc:
        return None, str(exc)


async def check_provider_ownership(service: str, subdomain: str) -> ProviderCheckResult:
    s = service.lower()

    if "github pages" in s:
        status, body = await _fetch(f"https://{subdomain}")
        claimable = status == 404 and "github pages site here" in body.lower()
        return ProviderCheckResult("github_pages", claimable, 20 if claimable else 0, "GitHub Pages error signature check", {"status": status})

    if "amazon s3" in s or "aws" in s:
        status, body = await _fetch(f"https://{subdomain}")
        claimable = "nosuchbucket" in body.lower() or "specified bucket does not exist" in body.lower()
        return ProviderCheckResult("aws_s3", claimable, 20 if claimable else 0, "S3 missing bucket signature check", {"status": status})

    if "vercel" in s:
        token = os.getenv("VERCEL_BEARER_TOKEN", "")
        hdr = {"Authorization": f"Bearer {token}"} if token else {}
        status, body = await _fetch(f"https://{subdomain}", hdr)
        claimable = "deployment not found" in body.lower()
        return ProviderCheckResult("vercel", claimable, 15 if claimable else 0, "Vercel deployment signature check", {"status": status, "token_used": bool(token)})

    if "netlify" in s:
        status, body = await _fetch(f"https://{subdomain}")
        claimable = "netlify-domain-not-found" in body.lower()
        return ProviderCheckResult("netlify", claimable, 15 if claimable else 0, "Netlify domain signature check", {"status": status})

    return ProviderCheckResult("generic", None, 0, "No provider-specific ownership check implemented", {})
