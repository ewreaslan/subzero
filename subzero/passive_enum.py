"""Passive subdomain enumeration sources."""

import json
import os
from typing import Iterable

import httpx


async def _crtsh(domain: str) -> list[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.get(url)
            data = r.json() if r.status_code == 200 else []
    except Exception:
        return []

    out = set()
    for row in data:
        name = row.get("name_value", "")
        for part in name.splitlines():
            p = part.strip().lower().lstrip("*.")
            if p.endswith(domain):
                out.add(p)
    return sorted(out)


async def _hackertarget(domain: str) -> list[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.get(url)
            if r.status_code != 200:
                return []
            lines = r.text.splitlines()
    except Exception:
        return []

    out = set()
    for line in lines:
        host = line.split(",", 1)[0].strip().lower()
        if host.endswith(domain):
            out.add(host)
    return sorted(out)


async def _shodan(domain: str) -> list[str]:
    key = os.getenv("SHODAN_API_KEY", "").strip()
    if not key:
        return []
    url = "https://api.shodan.io/dns/domain/" + domain
    params = {"key": key}
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.get(url, params=params)
            if r.status_code != 200:
                return []
            data = r.json()
    except Exception:
        return []

    out = set()
    for row in data.get("subdomains", []):
        host = f"{row}.{domain}".strip(".").lower()
        if host.endswith(domain):
            out.add(host)
    return sorted(out)


async def _censys(domain: str) -> list[str]:
    api_id = os.getenv("CENSYS_API_ID", "").strip()
    api_secret = os.getenv("CENSYS_API_SECRET", "").strip()
    if not api_id or not api_secret:
        return []
    url = "https://search.censys.io/api/v2/certificates/search"
    query = f"names: *.{domain}"
    payload = {"q": query, "per_page": 100}
    try:
        async with httpx.AsyncClient(timeout=4.0, auth=(api_id, api_secret)) as client:
            r = await client.post(url, json=payload)
            if r.status_code != 200:
                return []
            data = r.json()
    except Exception:
        return []

    out = set()
    hits = data.get("result", {}).get("hits", [])
    for hit in hits:
        for name in hit.get("names", []):
            n = str(name).lower().lstrip("*.").strip()
            if n.endswith(domain):
                out.add(n)
    return sorted(out)


async def _fofa(domain: str) -> list[str]:
    email = os.getenv("FOFA_EMAIL", "").strip()
    key = os.getenv("FOFA_KEY", "").strip()
    if not email or not key:
        return []
    query = f'domain=\"{domain}\"'
    qbase64 = __import__("base64").b64encode(query.encode()).decode()
    url = "https://fofa.info/api/v1/search/all"
    params = {"email": email, "key": key, "qbase64": qbase64, "fields": "host", "size": 100}
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.get(url, params=params)
            if r.status_code != 200:
                return []
            data = r.json()
    except Exception:
        return []

    out = set()
    for row in data.get("results", []):
        if not row:
            continue
        host = str(row[0]).lower().strip()
        host = host.split("://", 1)[-1].split("/", 1)[0]
        if host.endswith(domain):
            out.add(host)
    return sorted(out)


async def enumerate_passive(domain: str, sources: Iterable[str]) -> dict[str, list[str]]:
    srcs = {s.strip().lower() for s in sources}
    result: dict[str, list[str]] = {}
    if "crtsh" in srcs:
        result["crtsh"] = await _crtsh(domain)
    if "hackertarget" in srcs:
        result["hackertarget"] = await _hackertarget(domain)
    if "shodan" in srcs:
        result["shodan"] = await _shodan(domain)
    if "censys" in srcs:
        result["censys"] = await _censys(domain)
    if "fofa" in srcs:
        result["fofa"] = await _fofa(domain)

    return result
