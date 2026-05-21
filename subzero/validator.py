"""
Multi-layer confidence scoring engine.

Each validation signal contributes points independently.
A subdomain is only flagged VULNERABLE when multiple signals
agree — no single signal alone is sufficient (false-positive guard).

Scoring table
─────────────────────────────────────────────────────────────────────
Signal                                      │ Points
────────────────────────────────────────────│────────
CNAME matches known-dead-service pattern    │ fp.confidence_cname  (25–35)
NXDOMAIN confirmed by 4/4 resolvers         │ 40
NXDOMAIN confirmed by 3/4 resolvers         │ 30
NXDOMAIN confirmed by 2/4 resolvers         │  0  (not reliable)
HTTP body fingerprint match                 │ fp.confidence_body   (30–45)
HTTP status code matches expected           │ 15
Dangling CNAME (CNAME → NXDOMAIN)          │ 10
No A records returned by any resolver       │ 10
Service-specific validator confirms         │ 20
NS delegation to dead zone                  │ 35
─────────────────────────────────────────────────────────────────────

Verdict thresholds
─────────────────────────────────────────────────────────────────────
≥ 85  VULNERABLE  — multiple independent signals confirm
60–84 POTENTIAL   — strong indicators but incomplete confirmation
35–59 INVESTIGATE — weak/single signals, manual review needed
< 35  SAFE        — no credible takeover signal
─────────────────────────────────────────────────────────────────────
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

from .fingerprints import Fingerprint, match_cname, match_body
from .dns_resolver import DNSResult
from .http_prober import HTTPResult
from .learning import get_service_calibration


class Verdict(str, Enum):
    VULNERABLE  = "VULNERABLE"
    POTENTIAL   = "POTENTIAL"
    INVESTIGATE = "INVESTIGATE"
    SAFE        = "SAFE"


VERDICT_COLORS = {
    Verdict.VULNERABLE:  "bold red",
    Verdict.POTENTIAL:   "red",
    Verdict.INVESTIGATE: "yellow",
    Verdict.SAFE:        "green",
}

VERDICT_EMOJI = {
    Verdict.VULNERABLE:  "🔴",
    Verdict.POTENTIAL:   "🟠",
    Verdict.INVESTIGATE: "🟡",
    Verdict.SAFE:        "🟢",
}


@dataclass
class Signal:
    name: str
    points: int
    detail: str


@dataclass
class ValidationResult:
    subdomain: str
    verdict: Verdict
    confidence: int
    signals: list[Signal]
    fingerprint: Optional[Fingerprint]
    dns: DNSResult
    http: HTTPResult
    takeover_info: str = ""
    references: list[str] = field(default_factory=list)
    evidence_bundle: dict = field(default_factory=dict)
    verification_confirmed: bool = False

    @property
    def is_vulnerable(self) -> bool:
        return self.verdict == Verdict.VULNERABLE

    @property
    def worthy_of_report(self) -> bool:
        return self.verdict in (Verdict.VULNERABLE, Verdict.POTENTIAL, Verdict.INVESTIGATE)


def _confirmed_body_matches(http_result: HTTPResult) -> list[tuple[Fingerprint, str]]:
    """
    Confirm body fingerprints across multiple responses when possible.
    If multiple bodies exist, require the same phrase to appear in at least 2 bodies.
    If only one body exists, allow single-hit matching.
    """
    if not http_result.bodies:
        return []

    matches: list[tuple[Fingerprint, str]] = []
    required_hits = 2 if len(http_result.bodies) >= 2 else 1

    seen_services: set[str] = set()
    for fp, _ in match_body(http_result.body_combined):
        if fp.name in seen_services:
            continue
        seen_services.add(fp.name)
        for phrase in fp.http_fingerprints:
            hits = sum(1 for body in http_result.bodies if phrase.lower() in body.lower())
            if hits >= required_hits:
                matches.append((fp, phrase))
                break

    return matches


def evaluate(dns_result: DNSResult, http_result: HTTPResult) -> ValidationResult:
    """
    Core scoring function. Combines all signals into a final verdict.
    """
    subdomain   = dns_result.subdomain
    signals: list[Signal] = []
    confidence  = 0
    fingerprint: Optional[Fingerprint] = None

    # ── Signal 1: CNAME pattern match ────────────────────────────────────────
    cname_fp: Optional[Fingerprint] = None
    matched_cname: Optional[str] = None

    for cname in dns_result.cname_chain + ([dns_result.final_cname] if dns_result.final_cname else []):
        if cname:
            fp = match_cname(cname)
            if fp:
                cname_fp = fp
                matched_cname = cname
                break

    if cname_fp and matched_cname:
        fingerprint = cname_fp
        cal = get_service_calibration(cname_fp.name)
        pts = max(0, cname_fp.confidence_cname + cal.cname_delta)
        signals.append(Signal(
            name="CNAME fingerprint match",
            points=pts,
            detail=f"'{matched_cname}' → service: {cname_fp.name}",
        ))
        confidence += pts

    # ── Signal 2: NXDOMAIN consensus ─────────────────────────────────────────
    if dns_result.nxdomain_votes == 4:
        pts = 40
        signals.append(Signal(
            name="NXDOMAIN (4/4 resolvers)",
            points=pts,
            detail="All four independent resolvers return NXDOMAIN",
        ))
        confidence += pts
    elif dns_result.nxdomain_votes == 3:
        pts = 30
        signals.append(Signal(
            name="NXDOMAIN (3/4 resolvers)",
            points=pts,
            detail="Three of four resolvers return NXDOMAIN",
        ))
        confidence += pts
    elif dns_result.nxdomain_votes == 2:
        # Too ambiguous — log but do NOT add points (false-positive guard)
        signals.append(Signal(
            name="NXDOMAIN (2/4 resolvers) — inconclusive",
            points=0,
            detail="Only 2/4 resolvers agree; could be split-horizon or caching",
        ))

    # ── Signal 3: Dangling CNAME ──────────────────────────────────────────────
    if dns_result.dangling_cname:
        signals.append(Signal(
            name="Dangling CNAME",
            points=10,
            detail=f"CNAME chain ends at NXDOMAIN: {dns_result.final_cname}",
        ))
        confidence += 10

    # ── Signal 4: No A records from any resolver ──────────────────────────────
    if not dns_result.a_records and not dns_result.is_nxdomain:
        signals.append(Signal(
            name="No A records",
            points=10,
            detail="No A records returned by any resolver",
        ))
        confidence += 10

    # ── Signal 5: HTTP body fingerprint ──────────────────────────────────────
    body_matches = _confirmed_body_matches(http_result)
    for body_fp, phrase in body_matches:
        cal = get_service_calibration(body_fp.name)
        pts = max(0, body_fp.confidence_body + cal.body_delta)
        if fingerprint is None:
            fingerprint = body_fp
        elif fingerprint != body_fp:
            # CNAME and body fingerprints point to different services → suspicious
            # halve the body signal
            pts = pts // 2
            signals.append(Signal(
                name="HTTP body fingerprint (service mismatch — halved)",
                points=pts,
                detail=f"Body says '{body_fp.name}' but CNAME says '{fingerprint.name}'",
            ))
            confidence += pts
            continue

        signals.append(Signal(
            name="HTTP body fingerprint",
            points=pts,
            detail=f"Service: {body_fp.name}  |  phrase: \"{phrase}\"",
        ))
        confidence += pts
        break  # one match per service is enough

    # ── Signal 6: HTTP status code matches expected ───────────────────────────
    if fingerprint and http_result.status_code in fingerprint.status_codes:
        signals.append(Signal(
            name="HTTP status code match",
            points=15,
            detail=f"HTTP {http_result.status_code} matches expected for {fingerprint.name}",
        ))
        confidence += 15

    # ── Signal 7: NS zone delegation to dead zone ─────────────────────────────
    if dns_result.ns_delegation:
        signals.append(Signal(
            name="NS zone delegation (dead zone)",
            points=35,
            detail=f"NS records delegate to: {', '.join(dns_result.ns_records[:3])}",
        ))
        confidence += 35

    # DNS enrichment signals
    if dns_result.negative_ttl and dns_result.negative_ttl <= 300 and dns_result.nxdomain_votes >= 3:
        signals.append(Signal(
            name="Low negative TTL with NXDOMAIN",
            points=5,
            detail=f"SOA negative TTL={dns_result.negative_ttl}",
        ))
        confidence += 5

    # Counter-evidence / contradiction penalty
    contradiction = 0
    if dns_result.a_records or dns_result.aaaa_records:
        contradiction += 8
    if http_result.status_code and http_result.status_code in (200, 204):
        contradiction += 15
    if contradiction:
        signals.append(Signal(
            name="Counter-evidence penalty",
            points=-contradiction,
            detail="Live records or healthy HTTP response reduce takeover confidence",
        ))
        confidence -= contradiction

    # ── False-positive guard: require at least 2 distinct signal categories ───
    dns_signal_count  = sum(1 for s in signals if "NXDOMAIN" in s.name or "CNAME" in s.name or "NS zone" in s.name)
    http_signal_count = sum(1 for s in signals if "HTTP" in s.name)

    if confidence >= 85 and (dns_signal_count == 0 or http_signal_count == 0):
        # Only DNS or only HTTP signals — cap at POTENTIAL unless NS zone takeover
        if not dns_result.ns_delegation:
            confidence = min(confidence, 84)
            signals.append(Signal(
                name="FP guard: single-category signals",
                points=0,
                detail="Score capped at 84 — need both DNS and HTTP confirmation for VULNERABLE",
            ))

    confidence = max(0, confidence)

    # ── Verdict ───────────────────────────────────────────────────────────────
    if confidence >= 85:
        verdict = Verdict.VULNERABLE
    elif confidence >= 60:
        verdict = Verdict.POTENTIAL
    elif confidence >= 35:
        verdict = Verdict.INVESTIGATE
    else:
        verdict = Verdict.SAFE

    return ValidationResult(
        subdomain=subdomain,
        verdict=verdict,
        confidence=confidence,
        signals=signals,
        fingerprint=fingerprint,
        dns=dns_result,
        http=http_result,
        takeover_info=fingerprint.takeover_info if fingerprint else "",
        references=fingerprint.references if fingerprint else [],
        evidence_bundle={
            "dns": {
                "cname_chain": dns_result.cname_chain,
                "final_cname": dns_result.final_cname,
                "nxdomain_votes": dns_result.nxdomain_votes,
                "dangling_cname": dns_result.dangling_cname,
                "ns_delegation": dns_result.ns_delegation,
                "a_records": dns_result.a_records,
                "aaaa_records": dns_result.aaaa_records,
                "soa_mname": dns_result.soa_mname,
                "negative_ttl": dns_result.negative_ttl,
                "dnssec_supported": dns_result.dnssec_supported,
            },
            "http": {
                "reachable": http_result.reachable,
                "status_codes": http_result.status_codes,
                "final_urls": http_result.final_urls,
            },
            "signals": [
                {"name": s.name, "points": s.points, "detail": s.detail}
                for s in signals
            ],
            "risk": {
                "risk_score": 0,
                "contradiction_penalty": contradiction,
                "impact_tags": [],
            },
        },
    )
