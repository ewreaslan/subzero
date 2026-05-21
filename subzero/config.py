"""Typed config loader for subzero.yaml."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ScanConfig:
    profile: str = "balanced"
    concurrency: int = 50
    min_verdict: str = "INVESTIGATE"
    evidence: str = "full"
    explain: bool = True


@dataclass
class EnumerateConfig:
    sources: list[str] = field(default_factory=lambda: ["crtsh", "hackertarget"])


@dataclass
class SubzeroConfig:
    scan: ScanConfig = field(default_factory=ScanConfig)
    enumerate: EnumerateConfig = field(default_factory=EnumerateConfig)


def _merge_scan(scan: ScanConfig, data: dict[str, Any]) -> ScanConfig:
    return ScanConfig(
        profile=str(data.get("profile", scan.profile)),
        concurrency=int(data.get("concurrency", scan.concurrency)),
        min_verdict=str(data.get("min_verdict", scan.min_verdict)),
        evidence=str(data.get("evidence", scan.evidence)),
        explain=bool(data.get("explain", scan.explain)),
    )


def load_config(path: Path | None = None) -> SubzeroConfig:
    cfg = SubzeroConfig()
    p = path or Path("subzero.yaml")
    if not p.exists():
        return cfg

    raw = yaml.safe_load(p.read_text()) or {}
    if not isinstance(raw, dict):
        return cfg

    if isinstance(raw.get("scan"), dict):
        cfg.scan = _merge_scan(cfg.scan, raw["scan"])

    if isinstance(raw.get("enumerate"), dict):
        src = raw["enumerate"].get("sources")
        if isinstance(src, list):
            cfg.enumerate = EnumerateConfig(sources=[str(s).lower() for s in src])

    return cfg
