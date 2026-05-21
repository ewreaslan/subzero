"""
Async scan orchestrator.
Manages concurrency, per-subdomain pipeline, and result aggregation.
"""

import asyncio
import sys
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional

from .dns_resolver import resolve as dns_resolve
from .http_prober import probe as http_probe, HTTPResult
from .validator import evaluate, ValidationResult, Verdict, Signal
from .verifier import verify_candidate
from .provider_checks import check_provider_ownership

PER_TARGET_TIMEOUT = 20.0


def _verdict_from_confidence(confidence: int) -> Verdict:
    if confidence >= 85:
        return Verdict.VULNERABLE
    if confidence >= 60:
        return Verdict.POTENTIAL
    if confidence >= 35:
        return Verdict.INVESTIGATE
    return Verdict.SAFE


@dataclass
class ScanStats:
    total: int       = 0
    vulnerable: int  = 0
    potential: int   = 0
    investigate: int = 0
    safe: int        = 0
    errors: int      = 0


async def _scan_one(subdomain: str) -> Optional[ValidationResult]:
    """Full pipeline for a single subdomain."""
    subdomain = subdomain.strip().lower()
    if not subdomain or subdomain.startswith("#"):
        return None
    try:
        dns_result  = await dns_resolve(subdomain)
        if dns_result.resolver_unreachable:
            http_result = HTTPResult(
                subdomain=subdomain,
                reachable=False,
                errors=["HTTP probe skipped: DNS resolvers unreachable"],
            )
        else:
            http_result = await http_probe(subdomain)
        result = evaluate(dns_result, http_result)
        if result.verdict == Verdict.VULNERABLE and not dns_result.resolver_unreachable:
            expected_status = result.fingerprint.status_codes if result.fingerprint else []
            expected_phrases = result.fingerprint.http_fingerprints if result.fingerprint else []
            verify = await verify_candidate(
                subdomain=subdomain,
                nxdomain_target=dns_result.final_cname or subdomain,
                expected_status_codes=expected_status,
                expected_phrases=expected_phrases,
            )
            result.verification_confirmed = verify.confirmed
            result.evidence_bundle["verification"] = {
                "confirmed": verify.confirmed,
                "score": verify.score,
                "dig_cname": verify.evidence.dig_cname,
                "nxdomain_target": verify.evidence.nxdomain_target,
                "nxdomain_votes_two_resolvers": verify.evidence.nxdomain_votes_two_resolvers,
                "curl_http_status": verify.evidence.curl_http_status,
                "curl_http_headers": verify.evidence.curl_http_headers,
                "curl_http_body_snippet": verify.evidence.curl_http_body_snippet,
                "notes": verify.evidence.notes,
            }
            if not verify.confirmed:
                result.signals.append(Signal(
                    name="Second-pass verification failed",
                    points=0,
                    detail="Auto verification did not confirm takeover evidence",
                ))
                if result.confidence >= 60:
                    result.verdict = Verdict.POTENTIAL
                else:
                    result.verdict = Verdict.INVESTIGATE
            if result.fingerprint:
                provider = await check_provider_ownership(result.fingerprint.name, subdomain)
                result.evidence_bundle["provider_ownership_check"] = {
                    "provider": provider.provider,
                    "claimable": provider.claimable,
                    "confidence": provider.confidence,
                    "detail": provider.detail,
                    "raw": provider.raw,
                }
                if provider.claimable:
                    result.confidence += provider.confidence
                elif provider.claimable is False:
                    result.confidence = max(0, result.confidence - 10)

        result.confidence = max(0, result.confidence)
        result.verdict = _verdict_from_confidence(result.confidence)

        risk_score = result.confidence
        impact_tags: list[str] = []
        host = subdomain.lower()
        if any(x in host for x in ("admin", "api", "auth", "login")):
            risk_score += 15
            impact_tags.append("high_value_subdomain")
        if any(x in host for x in ("dev", "staging", "test", "internal")):
            risk_score += 10
            impact_tags.append("non_prod_exposed")
        result.evidence_bundle["risk"]["risk_score"] = min(100, max(0, risk_score))
        result.evidence_bundle["risk"]["impact_tags"] = impact_tags
        return result
    except Exception:
        return None


async def scan_stream(
    subdomains: list[str],
    concurrency: int = 50,
    only_vulnerable: bool = False,
    min_verdict: str = "INVESTIGATE",
    profile: str = "balanced",
) -> AsyncIterator[ValidationResult]:
    """
    Async generator — yields ValidationResult as each subdomain finishes.
    Controls concurrency via semaphore.
    """
    profile = profile.lower().strip()
    if profile == "fast":
        concurrency = min(200, max(concurrency, 100))
    elif profile == "strict":
        concurrency = min(concurrency, 30)

    semaphore = asyncio.Semaphore(concurrency)
    verdict_order = [v.value for v in Verdict]
    min_verdict = min_verdict.upper().strip()
    if min_verdict not in verdict_order:
        min_verdict = "INVESTIGATE"

    async def _worker(sub: str):
        async with semaphore:
            try:
                return await asyncio.wait_for(
                    _scan_one(sub),
                    timeout=PER_TARGET_TIMEOUT,
                )
            except asyncio.TimeoutError:
                return None

    tasks = [asyncio.create_task(_worker(s)) for s in subdomains if s.strip()]

    for coro in asyncio.as_completed(tasks):
        result = await coro
        if result is None:
            continue
        if only_vulnerable and result.verdict != Verdict.VULNERABLE:
            continue
        if result.verdict.value not in verdict_order[:verdict_order.index(min_verdict) + 1]:
            continue
        yield result


def read_subdomains(source: str) -> list[str]:
    """
    Read subdomains from a file path or '-' for stdin.
    Handles subfinder / amass / plain-text output:
      - strips whitespace, blank lines, comments (#)
      - handles lines with IP suffix: 'sub.domain.com 1.2.3.4'
    """
    lines: list[str] = []

    if source == "-":
        raw = sys.stdin.read()
    else:
        with open(source, "r", errors="ignore") as fh:
            raw = fh.read()

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # subfinder sometimes outputs: sub.target.com [1.2.3.4]
        sub = line.split()[0].rstrip(".")
        if "." in sub:
            lines.append(sub)

    return list(dict.fromkeys(lines))  # deduplicate, preserve order
