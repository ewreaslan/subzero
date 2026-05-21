"""
Multi-resolver DNS engine.

All NXDOMAIN / dangling conclusions require consensus from at least
MIN_CONFIRMING_RESOLVERS out of RESOLVERS before being trusted.
This eliminates single-resolver false positives (caching, split-horizon DNS, etc.)
"""

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Optional

import dns.asyncresolver
import dns.resolver
import dns.exception
import dns.name
import dns.rdatatype

# Four independent public resolvers
RESOLVERS = [
    ("Google Primary",    "8.8.8.8"),
    ("Google Secondary",  "8.8.4.4"),
    ("Cloudflare",        "1.1.1.1"),
    ("Quad9",             "9.9.9.9"),
]

MIN_CONFIRMING_RESOLVERS = 3   # NXDOMAIN needs 3/4 agreement
CNAME_CHAIN_LIMIT        = 10  # prevent infinite loops
DNS_TIMEOUT              = 5.0


@dataclass
class DNSResult:
    subdomain: str
    cname_chain: list[str]          = field(default_factory=list)
    final_cname: Optional[str]      = None
    a_records: list[str]            = field(default_factory=list)
    aaaa_records: list[str]         = field(default_factory=list)
    ns_records: list[str]           = field(default_factory=list)
    soa_mname: Optional[str]        = None
    negative_ttl: Optional[int]     = None
    dnssec_supported: bool          = False
    is_nxdomain: bool               = False
    nxdomain_votes: int             = 0          # how many resolvers agree
    nxdomain_confirmed: bool        = False      # >= MIN_CONFIRMING_RESOLVERS
    dangling_cname: bool            = False      # CNAME exists but resolves to NXDOMAIN
    ns_delegation: bool             = False      # has NS records (zone takeover possible)
    errors: list[str]               = field(default_factory=list)
    raw_resolver_responses: dict    = field(default_factory=dict)  # per-resolver debug
    resolver_unreachable: bool      = False


async def _query_one_resolver(
    resolver_name: str,
    resolver_ip: str,
    domain: str,
    rdtype: str,
) -> tuple[str, list[str], bool, Optional[str]]:
    """
    Query a single resolver for rdtype records on domain.
    Returns (resolver_name, records, is_nxdomain, error)
    """
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [resolver_ip]
    resolver.lifetime = DNS_TIMEOUT

    try:
        answer = await resolver.resolve(domain, rdtype)
        records = [str(r) for r in answer]
        return resolver_name, records, False, None
    except dns.resolver.NXDOMAIN:
        return resolver_name, [], True, None
    except dns.resolver.NoAnswer:
        return resolver_name, [], False, None
    except dns.resolver.NoNameservers:
        return resolver_name, [], False, "NoNameservers"
    except dns.exception.Timeout:
        return resolver_name, [], False, "Timeout"
    except Exception as exc:
        return resolver_name, [], False, str(exc)


async def _resolve_cname_chain(domain: str) -> list[str]:
    """
    Follow CNAME chain using the system resolver (best-effort).
    Returns list of CNAMEs in order, stripped of trailing dots.
    """
    chain: list[str] = []
    current = domain
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT

    for _ in range(CNAME_CHAIN_LIMIT):
        try:
            answer = await resolver.resolve(current, "CNAME")
            target = str(answer[0].target).rstrip(".")
            if target in chain:
                break  # loop detected
            chain.append(target)
            current = target
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            break

    return chain


async def _check_nxdomain_consensus(domain: str) -> tuple[int, dict]:
    """
    Query all resolvers for A record.
    Returns (vote_count_nxdomain, per_resolver_detail).
    """
    tasks = [
        _query_one_resolver(name, ip, domain, "A")
        for name, ip in RESOLVERS
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    nxdomain_count = 0
    detail: dict = {}

    for res in results:
        if isinstance(res, Exception):
            continue
        r_name, records, is_nx, error = res
        detail[r_name] = {
            "nxdomain": is_nx,
            "records": records,
            "error": error,
        }
        if is_nx:
            nxdomain_count += 1

    return nxdomain_count, detail


async def _get_ns_records(domain: str) -> list[str]:
    """Check for NS records (zone delegation)."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    try:
        answer = await resolver.resolve(domain, "NS")
        return [str(r).rstrip(".") for r in answer]
    except Exception:
        return []


async def _get_aaaa_records(domain: str) -> list[str]:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    try:
        answer = await resolver.resolve(domain, "AAAA")
        return [str(r) for r in answer]
    except Exception:
        return []


async def _get_soa_meta(domain: str) -> tuple[Optional[str], Optional[int]]:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    try:
        answer = await resolver.resolve(domain, "SOA")
        soa = answer[0]
        return str(soa.mname).rstrip("."), int(soa.minimum)
    except Exception:
        return None, None


async def _check_dnssec(domain: str) -> bool:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    try:
        await resolver.resolve(domain, "DNSKEY")
        return True
    except Exception:
        return False


async def resolve(subdomain: str) -> DNSResult:
    """
    Full multi-layer DNS analysis of a subdomain.
    This is the primary entry point for the scanner.
    """
    result = DNSResult(subdomain=subdomain)

    # Hard fast-fail for restricted environments: if none of the resolver
    # endpoints are reachable over TCP/53, avoid long async DNS waits.
    any_reachable = False
    for _name, ip in RESOLVERS:
        try:
            with socket.create_connection((ip, 53), timeout=0.35):
                any_reachable = True
                break
        except Exception:
            continue
    if not any_reachable:
        result.resolver_unreachable = True
        result.errors.append("Public DNS resolvers not reachable from this environment")
        return result

    # Step 1: follow CNAME chain
    cname_chain = await _resolve_cname_chain(subdomain)
    result.cname_chain = cname_chain
    if cname_chain:
        result.final_cname = cname_chain[-1]

    # Step 2: check NXDOMAIN with consensus from multiple resolvers
    target_to_check = result.final_cname if result.final_cname else subdomain
    nxdomain_votes, resolver_detail = await _check_nxdomain_consensus(target_to_check)

    result.nxdomain_votes = nxdomain_votes
    result.raw_resolver_responses = resolver_detail
    result.nxdomain_confirmed = nxdomain_votes >= MIN_CONFIRMING_RESOLVERS

    # Fast-fail: if all resolvers are unreachable, skip expensive enrichment.
    if resolver_detail:
        all_unreachable = all(
            (d.get("error") in {"NoNameservers", "Timeout"}) and not d.get("records") and not d.get("nxdomain")
            for d in resolver_detail.values()
        )
        if all_unreachable:
            result.resolver_unreachable = True
            result.errors.append("All public resolvers unreachable (NoNameservers/Timeout)")
            return result

    if result.nxdomain_confirmed:
        result.is_nxdomain = True
        if result.final_cname:
            result.dangling_cname = True

    # Step 3: if CNAME resolves, grab A records from majority
    if not result.nxdomain_confirmed:
        for _name, detail in resolver_detail.items():
            if detail["records"]:
                result.a_records = detail["records"]
                break
    result.aaaa_records = await _get_aaaa_records(target_to_check)

    # Step 4: NS record check (zone delegation takeover)
    ns = await _get_ns_records(subdomain)
    if ns:
        result.ns_records = ns
        # Mark as potentially dangling only when at least one delegated NS
        # is strongly confirmed NXDOMAIN (same confidence model as normal checks).
        for ns_host in ns[:4]:
            ns_votes, _ = await _check_nxdomain_consensus(ns_host)
            if ns_votes >= MIN_CONFIRMING_RESOLVERS:
                result.ns_delegation = True
                break

    # Step 5: SOA and DNSSEC enrichment
    soa_mname, negative_ttl = await _get_soa_meta(subdomain)
    result.soa_mname = soa_mname
    result.negative_ttl = negative_ttl
    result.dnssec_supported = await _check_dnssec(subdomain)

    return result
