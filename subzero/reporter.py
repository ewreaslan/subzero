"""
Output formatters: Rich terminal table, JSON, Markdown report.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .validator import ValidationResult, Verdict, VERDICT_COLORS, VERDICT_EMOJI

console = Console()


def _verdict_text(v: Verdict) -> Text:
    t = Text()
    t.append(f"{VERDICT_EMOJI[v]} {v.value}", style=VERDICT_COLORS[v])
    return t


def print_result_live(result: ValidationResult) -> None:
    """Print a single result line as scan progresses."""
    if result.verdict == Verdict.SAFE:
        return

    fp_name = result.fingerprint.name if result.fingerprint else "Unknown"
    cname   = result.dns.final_cname or "-"

    line = Text()
    line.append(f"  {VERDICT_EMOJI[result.verdict]} ", style=VERDICT_COLORS[result.verdict])
    line.append(f"{result.subdomain:<45}", style="white bold" if result.is_vulnerable else "white")
    line.append(f"  {fp_name:<20}", style="cyan")
    line.append(f"  score={result.confidence:<4}", style="dim")
    line.append(f"  cname={cname}", style="dim")

    console.print(line)


def print_summary_table(results: list[ValidationResult]) -> None:
    """Print the final summary table."""
    vuln   = [r for r in results if r.verdict == Verdict.VULNERABLE]
    pot    = [r for r in results if r.verdict == Verdict.POTENTIAL]
    inv    = [r for r in results if r.verdict == Verdict.INVESTIGATE]
    safe   = [r for r in results if r.verdict == Verdict.SAFE]

    console.print()
    console.print(Panel(
        f"  [bold red]VULNERABLE[/bold red]   {len(vuln):>4}\n"
        f"  [red]POTENTIAL[/red]    {len(pot):>4}\n"
        f"  [yellow]INVESTIGATE[/yellow]  {len(inv):>4}\n"
        f"  [green]SAFE[/green]         {len(safe):>4}\n"
        f"  [dim]TOTAL        {len(results):>4}[/dim]",
        title="[bold]Scan Summary[/bold]",
        expand=False,
    ))

    noteworthy = vuln + pot + inv
    if not noteworthy:
        console.print("[green]No takeover candidates found.[/green]")
        return

    table = Table(
        title="\n[bold]Findings[/bold]",
        show_header=True,
        header_style="bold blue",
        show_lines=True,
    )
    table.add_column("Verdict",    width=13, no_wrap=True)
    table.add_column("Score",      width=6,  justify="right")
    table.add_column("Risk",       width=6,  justify="right")
    table.add_column("Subdomain",  style="white bold", overflow="fold")
    table.add_column("Service",    style="cyan", width=20)
    table.add_column("CNAME",      style="dim",  overflow="fold")
    table.add_column("DNS Votes",  width=10, justify="center")
    table.add_column("Signals",    overflow="fold")

    for r in sorted(noteworthy, key=lambda x: -x.confidence):
        cname    = r.dns.final_cname or (r.dns.cname_chain[-1] if r.dns.cname_chain else "-")
        service  = r.fingerprint.name if r.fingerprint else "Unknown"
        nx_votes = f"{r.dns.nxdomain_votes}/4" if r.dns.nxdomain_votes else "-"
        sig_text = "; ".join(s.name for s in r.signals if s.points > 0)

        table.add_row(
            _verdict_text(r.verdict),
            str(r.confidence),
            str(r.evidence_bundle.get("risk", {}).get("risk_score", "-")),
            r.subdomain,
            service,
            cname,
            nx_votes,
            sig_text,
        )

    console.print(table)

    # Per-finding detail for VULNERABLE
    for r in vuln:
        _print_detail(r)


def build_explanation(result: ValidationResult) -> str:
    parts = [
        f"Verdict={result.verdict.value}, confidence={result.confidence}",
        f"risk_score={result.evidence_bundle.get('risk', {}).get('risk_score', '-')}",
    ]
    positive = [s for s in result.signals if s.points > 0]
    penalties = [s for s in result.signals if s.points < 0]
    if positive:
        parts.append("Top positive signals: " + "; ".join(f"{s.name}(+{s.points})" for s in positive[:3]))
    if penalties:
        parts.append("Penalties: " + "; ".join(f"{s.name}({s.points})" for s in penalties[:2]))
    v = result.evidence_bundle.get("verification", {})
    if v:
        parts.append(f"Second-pass confirmed={v.get('confirmed')} score={v.get('score')}")
    p = result.evidence_bundle.get("provider_ownership_check", {})
    if p:
        parts.append(f"Provider check: {p.get('provider')} claimable={p.get('claimable')}")
    return " | ".join(parts)


def _print_detail(r: ValidationResult) -> None:
    """Detailed signal breakdown for VULNERABLE findings."""
    lines = []
    for s in r.signals:
        if s.points > 0:
            lines.append(f"  [cyan]+{s.points:>3}[/cyan]  {s.name}: [dim]{s.detail}[/dim]")
        else:
            lines.append(f"  [dim]  {s.points:>3}  {s.name}: {s.detail}[/dim]")

    if r.takeover_info:
        lines.append(f"\n  [bold]How to take over:[/bold] {r.takeover_info}")
    for ref in r.references[:2]:
        lines.append(f"  [dim]Ref: {ref}[/dim]")

    console.print(Panel(
        "\n".join(lines),
        title=f"[bold red]🔴 {r.subdomain}[/bold red]  [dim](score: {r.confidence})[/dim]",
        border_style="red",
        expand=False,
    ))


def export_json(results: list[ValidationResult], path: Path) -> None:
    """Export all results as structured JSON."""
    def _ser(r: ValidationResult) -> dict:
        evidence = r.evidence_bundle or {}
        return {
            "subdomain": r.subdomain,
            "verdict": r.verdict.value,
            "confidence": r.confidence,
            "service": r.fingerprint.name if r.fingerprint else None,
            "cname_chain": r.dns.cname_chain,
            "final_cname": r.dns.final_cname,
            "nxdomain_votes": r.dns.nxdomain_votes,
            "nxdomain_confirmed": r.dns.nxdomain_confirmed,
            "a_records": r.dns.a_records,
            "http_reachable": r.http.reachable,
            "http_status": r.http.status_code,
            "signals": [{"name": s.name, "points": s.points, "detail": s.detail} for s in r.signals],
            "takeover_info": r.takeover_info,
            "references": r.references,
            "verification_confirmed": r.verification_confirmed,
            "evidence_bundle": evidence,
        }

    out = {
        "meta": {
            "tool": "subzero",
            "generated": datetime.now(timezone.utc).isoformat(),
            "total": len(results),
            "vulnerable": sum(1 for r in results if r.verdict == Verdict.VULNERABLE),
            "potential": sum(1 for r in results if r.verdict == Verdict.POTENTIAL),
        },
        "results": [_ser(r) for r in results],
    }
    path.write_text(json.dumps(out, indent=2))


def export_markdown(results: list[ValidationResult], path: Path) -> None:
    """Export a Markdown report suitable for bug bounty submissions."""
    noteworthy = [r for r in results if r.verdict in (Verdict.VULNERABLE, Verdict.POTENTIAL)]
    lines = [
        "# Subdomain Takeover Report",
        f"*Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*",
        f"*Tool: subzero*",
        "",
        "## Summary",
        f"| Verdict | Count |",
        f"|---------|-------|",
        f"| 🔴 VULNERABLE | {sum(1 for r in results if r.verdict == Verdict.VULNERABLE)} |",
        f"| 🟠 POTENTIAL  | {sum(1 for r in results if r.verdict == Verdict.POTENTIAL)} |",
        f"| 🟡 INVESTIGATE| {sum(1 for r in results if r.verdict == Verdict.INVESTIGATE)} |",
        "",
        "## Findings",
    ]

    for r in sorted(noteworthy, key=lambda x: -x.confidence):
        emoji   = VERDICT_EMOJI[r.verdict]
        service = r.fingerprint.name if r.fingerprint else "Unknown"
        cname   = r.dns.final_cname or "-"

        lines += [
            f"### {emoji} {r.subdomain}",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Verdict | **{r.verdict.value}** (score: {r.confidence}) |",
            f"| Risk score | {r.evidence_bundle.get('risk', {}).get('risk_score', '-')} |",
            f"| Service | {service} |",
            f"| CNAME | `{cname}` |",
            f"| NXDOMAIN votes | {r.dns.nxdomain_votes}/4 resolvers |",
            f"| HTTP reachable | {r.http.reachable} |",
            f"| HTTP status | {r.http.status_code or '-'} |",
            f"| Verification confirmed | {r.verification_confirmed} |",
            "",
            "**Signals:**",
            "",
        ]
        for s in r.signals:
            if s.points > 0:
                lines.append(f"- **+{s.points}** {s.name}: {s.detail}")
        lines.append("")

        if r.takeover_info:
            lines += [f"**How to take over:** {r.takeover_info}", ""]
        if r.evidence_bundle.get("verification"):
            v = r.evidence_bundle["verification"]
            lines += [
                "**Evidence Bundle (Second-pass):**",
                "",
                f"- confirmed: {v.get('confirmed')}",
                f"- score: {v.get('score')}",
                f"- dig cname: {', '.join(v.get('dig_cname', [])) or '(none)'}",
                f"- nxdomain votes (2 resolvers): {v.get('nxdomain_votes_two_resolvers')}",
                f"- curl status: {v.get('curl_http_status')}",
                "",
            ]
        for ref in r.references:
            lines.append(f"- {ref}")
        lines.append("")

    path.write_text("\n".join(lines))
