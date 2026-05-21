"""Feedback loop: store TP/FP labels and calibrate service weights."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


DEFAULT_DB = Path(".subzero_feedback.json")


@dataclass
class ServiceCalibration:
    cname_delta: int = 0
    body_delta: int = 0


def _load(path: Path = DEFAULT_DB) -> dict:
    if not path.exists():
        return {"labels": [], "calibration": {}}
    return json.loads(path.read_text())


def _save(data: dict, path: Path = DEFAULT_DB) -> None:
    path.write_text(json.dumps(data, indent=2))


def record_label(subdomain: str, service: str, verdict: str, label: str, path: Path = DEFAULT_DB) -> None:
    data = _load(path)
    data["labels"].append({
        "subdomain": subdomain,
        "service": service,
        "verdict": verdict,
        "label": label,
    })
    _save(data, path)


def recompute_calibration(path: Path = DEFAULT_DB) -> dict[str, ServiceCalibration]:
    data = _load(path)
    by_service: dict[str, dict[str, int]] = {}

    for row in data.get("labels", []):
        s = row.get("service") or "unknown"
        by_service.setdefault(s, {"tp": 0, "fp": 0})
        if row.get("label") == "tp":
            by_service[s]["tp"] += 1
        elif row.get("label") == "fp":
            by_service[s]["fp"] += 1

    cal: dict[str, ServiceCalibration] = {}
    serial: dict[str, dict[str, int]] = {}
    for s, m in by_service.items():
        delta = 0
        if m["fp"] >= 3 and m["fp"] > m["tp"]:
            delta = -5
        elif m["tp"] >= 3 and m["tp"] > m["fp"]:
            delta = 3
        cal[s] = ServiceCalibration(cname_delta=delta, body_delta=delta)
        serial[s] = {"cname_delta": delta, "body_delta": delta}

    data["calibration"] = serial
    _save(data, path)
    return cal


def get_service_calibration(service: str, path: Path = DEFAULT_DB) -> ServiceCalibration:
    data = _load(path)
    d = data.get("calibration", {}).get(service, {})
    return ServiceCalibration(cname_delta=int(d.get("cname_delta", 0)), body_delta=int(d.get("body_delta", 0)))
