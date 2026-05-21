#!/usr/bin/env python3
import json
from pathlib import Path

from subzero.dns_resolver import DNSResult
from subzero.http_prober import HTTPResult
from subzero.validator import evaluate


def build_dns(d):
    return DNSResult(
        subdomain=d["subdomain"],
        cname_chain=d["cname_chain"],
        final_cname=d["final_cname"],
        a_records=d["a_records"],
        ns_records=d["ns_records"],
        is_nxdomain=d["is_nxdomain"],
        nxdomain_votes=d["nxdomain_votes"],
        nxdomain_confirmed=d["nxdomain_confirmed"],
        dangling_cname=d["dangling_cname"],
        ns_delegation=d["ns_delegation"],
    )


def build_http(h, subdomain):
    return HTTPResult(
        subdomain=subdomain,
        reachable=h["reachable"],
        status_codes=h["status_codes"],
        final_urls=h["final_urls"],
        bodies=h["bodies"],
        headers_list=h["headers_list"],
        errors=h["errors"],
    )


def main():
    cases = json.loads(Path("tests/fixtures/cases.json").read_text())

    tp = fp = tn = fn = 0
    rows = []

    for case in cases:
        dns = build_dns(case["dns"])
        http = build_http(case["http"], case["dns"]["subdomain"])
        pred = evaluate(dns, http).verdict.value
        exp = case["expected"]

        pred_pos = pred in {"VULNERABLE", "POTENTIAL"}
        exp_pos = exp in {"VULNERABLE", "POTENTIAL"}

        if pred_pos and exp_pos:
            tp += 1
        elif pred_pos and not exp_pos:
            fp += 1
        elif not pred_pos and exp_pos:
            fn += 1
        else:
            tn += 1

        rows.append((case["name"], exp, pred))

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0

    print("| Metric | Value |")
    print("|---|---:|")
    print(f"| TP | {tp} |")
    print(f"| FP | {fp} |")
    print(f"| TN | {tn} |")
    print(f"| FN | {fn} |")
    print(f"| Precision | {precision:.3f} |")
    print(f"| Recall | {recall:.3f} |")
    print("\n| Case | Expected | Predicted |")
    print("|---|---|---|")
    for name, exp, pred in rows:
        print(f"| {name} | {exp} | {pred} |")

    if fp > 0 or fn > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
