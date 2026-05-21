"""
Second-pass verification engine for high-confidence findings.

This module performs independent checks for candidates:
  - dig-style CNAME confirmation
  - NXDOMAIN re-check via two resolvers
  - curl -i style HTTP validation (status + headers + body snippet)
"""

import asyncio
from dataclasses import dataclass, field
from typing import Optional

import dns.asyncresolver
import dns.resolver
import httpx


VERIFY_RESOLVERS = ["1.1.1.1", "8.8.8.8"]
VERIFY_DNS_TIMEOUT = 5.0
VERIFY_HTTP_TIMEOUT = 12.0


@dataclass
class VerificationEvidence:
    dig_cname: list[str] = field(default_factory=list)
    nxdomain_votes_two_resolvers: int = 0
    nxdomain_target: Optional[str] = None
    curl_http_status: Optional[int] = None
    curl_http_headers: dict = field(default_factory=dict)
    curl_http_body_snippet: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass
class VerificationResult:
    confirmed: bool
    score: int
    evidence: VerificationEvidence


async def _resolve_cname_once(subdomain: str) -> list[str]:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = VERIFY_DNS_TIMEOUT
    try:
        ans = await resolver.resolve(subdomain, "CNAME")
        return [str(x.target).rstrip(".") for x in ans]
    except Exception:
        return []


async def _nxdomain_votes_two_resolvers(host: str) -> int:
    async def _one(ns: str) -> int:
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = [ns]
        resolver.lifetime = VERIFY_DNS_TIMEOUT
        try:
            await resolver.resolve(host, "A")
            return 0
        except dns.resolver.NXDOMAIN:
            return 1
        except Exception:
            return 0

    results = await asyncio.gather(*[_one(ns) for ns in VERIFY_RESOLVERS], return_exceptions=True)
    votes = 0
    for r in results:
        if isinstance(r, int):
            votes += r
    return votes


async def _curl_i_like(subdomain: str) -> tuple[Optional[int], dict, str]:
    urls = [f"https://{subdomain}", f"http://{subdomain}"]
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=VERIFY_HTTP_TIMEOUT,
        verify=False,
        headers={"User-Agent": "curl/8.5.0"},
    ) as client:
        tasks = [client.get(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, Exception):
            continue
        return r.status_code, dict(r.headers), r.text[:2048]
    return None, {}, ""


async def verify_candidate(
    subdomain: str,
    nxdomain_target: Optional[str],
    expected_status_codes: list[int],
    expected_phrases: list[str],
) -> VerificationResult:
    evidence = VerificationEvidence()

    dig_cname = await _resolve_cname_once(subdomain)
    evidence.dig_cname = dig_cname
    if dig_cname:
        evidence.notes.append("dig-style CNAME check found CNAME records")
    else:
        evidence.notes.append("dig-style CNAME check found no CNAME records")

    target = nxdomain_target or subdomain
    evidence.nxdomain_target = target
    nx_votes = await _nxdomain_votes_two_resolvers(target)
    evidence.nxdomain_votes_two_resolvers = nx_votes
    evidence.notes.append(f"Two-resolver NXDOMAIN votes: {nx_votes}/2")

    status, headers, body = await _curl_i_like(subdomain)
    evidence.curl_http_status = status
    evidence.curl_http_headers = headers
    evidence.curl_http_body_snippet = body

    score = 0
    if dig_cname:
        score += 20
    if nx_votes == 2:
        score += 35
    elif nx_votes == 1:
        score += 10

    if status is not None and status in expected_status_codes:
        score += 20
        evidence.notes.append(f"curl-style HTTP status matched expected: {status}")
    elif status is not None:
        evidence.notes.append(f"curl-style HTTP status observed: {status}")
    else:
        evidence.notes.append("curl-style HTTP request failed for both HTTPS and HTTP")

    body_lower = body.lower()
    phrase_match = False
    for phrase in expected_phrases:
        if phrase.lower() in body_lower:
            phrase_match = True
            score += 25
            evidence.notes.append(f"curl-style body matched phrase: {phrase}")
            break

    confirmed = score >= 55 and (nx_votes >= 1 or phrase_match)
    return VerificationResult(confirmed=confirmed, score=score, evidence=evidence)
