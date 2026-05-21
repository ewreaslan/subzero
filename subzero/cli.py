#!/usr/bin/env python3
import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from subzero.scanner import scan_stream, read_subdomains, ScanStats
from subzero.fingerprints import FINGERPRINTS
from subzero.reporter import (
    print_result_live, print_summary_table,
    export_json, export_markdown, console, build_explanation
)
from subzero.validator import Verdict
from subzero.dns_resolver import resolve as dns_resolve
from subzero.http_prober import probe as http_probe
from subzero.http_prober import HTTPResult
from subzero.validator import evaluate
from subzero.verifier import verify_candidate
from subzero.passive_enum import enumerate_passive
from subzero.learning import record_label, recompute_calibration
from subzero.config import load_config

app = typer.Typer(
    name="subzero",
    help="Subdomain Takeover Scanner — multi-layer, false-positive resistant",
    add_completion=False,
    rich_markup_mode="rich",
)

BANNER = """[bold cyan]
███████╗██╗   ██╗██████╗ ███████╗███████╗██████╗  ██████╗ 
██╔════╝██║   ██║██╔══██╗╚══███╔╝██╔════╝██╔══██╗██╔═══██╗
███████╗██║   ██║██████╔╝  ███╔╝ █████╗  ██████╔╝██║   ██║
╚════██║██║   ██║██╔══██╗ ███╔╝  ██╔══╝  ██╔══██╗██║   ██║
███████║╚██████╔╝██████╔╝███████╗███████╗██║  ██║╚██████╔╝
╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ [/bold cyan]
[dim]Subdomain Takeover Scanner  |  linkedin.com/in/emreaslany
"""


def _banner():
    console.print(BANNER)


async def _bounded(coro, timeout: float = 20.0):
    return await asyncio.wait_for(coro, timeout=timeout)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        _banner()
        console.print(ctx.get_help())
        raise typer.Exit()


# ── scan ──────────────────────────────────────────────────────────────────────

@app.command("scan", help="Scan subdomains for takeover vulnerabilities")
def cmd_scan(
    target: Optional[str] = typer.Argument(
        None,
        help="Single domain to scan (e.g. sub.target.com)",
    ),
    file: Optional[Path] = typer.Option(
        None, "--file", "-f",
        help="File with subdomains (one per line). Use '-' for stdin.",
    ),
    concurrency: int = typer.Option(
        50, "--concurrency", "-c",
        help="Concurrent scan workers (default: 50)",
    ),
    only_vulnerable: bool = typer.Option(
        False, "--only-vulnerable", "-V",
        help="Only show VULNERABLE results",
    ),
    min_verdict: str = typer.Option(
        "INVESTIGATE", "--min-verdict",
        help="Minimum verdict to display: VULNERABLE | POTENTIAL | INVESTIGATE",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Output file path (.json or .md)",
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q",
        help="Suppress live output — only print final summary",
    ),
    profile: str = typer.Option(
        "balanced", "--profile",
        help="Scan profile: strict | balanced | fast",
    ),
    evidence_level: str = typer.Option(
        "full", "--evidence",
        help="Evidence mode: min | full",
    ),
    explain: bool = typer.Option(
        False, "--explain",
        help="Include plain-language explanation for each non-safe finding",
    ),
    config: Optional[Path] = typer.Option(
        None, "--config",
        help="Path to subzero.yaml (default: ./subzero.yaml if present)",
    ),
):
    _banner()
    cfg = load_config(config)
    allowed_profiles = {"strict", "balanced", "fast"}
    allowed_evidence = {"min", "full"}
    allowed_min_verdict = {"VULNERABLE", "POTENTIAL", "INVESTIGATE"}

    profile = (profile or cfg.scan.profile).lower().strip()
    evidence_level = (evidence_level or cfg.scan.evidence).lower().strip()
    min_verdict = (min_verdict or cfg.scan.min_verdict).upper().strip()
    if concurrency == 50 and cfg.scan.concurrency != 50:
        concurrency = cfg.scan.concurrency
    if not explain and cfg.scan.explain:
        explain = True

    if concurrency < 1:
        console.print("[red]Invalid --concurrency:[/red] must be >= 1")
        console.print("[dim]Example: subzero scan scanme.example.org -c 50[/dim]")
        raise typer.Exit(2)
    if profile not in allowed_profiles:
        console.print(f"[red]Invalid --profile:[/red] {profile}")
        console.print("[dim]Allowed: strict, balanced, fast[/dim]")
        raise typer.Exit(2)
    if evidence_level not in allowed_evidence:
        console.print(f"[red]Invalid --evidence:[/red] {evidence_level}")
        console.print("[dim]Allowed: min, full[/dim]")
        raise typer.Exit(2)
    if min_verdict not in allowed_min_verdict:
        console.print(f"[red]Invalid --min-verdict:[/red] {min_verdict}")
        console.print("[dim]Allowed: VULNERABLE, POTENTIAL, INVESTIGATE[/dim]")
        raise typer.Exit(2)

    # Build subdomain list
    subdomains: list[str] = []

    if target:
        subdomains.append(target.strip())

    if file:
        src = "-" if str(file) == "-" else str(file)
        if src != "-" and not Path(src).exists():
            console.print(f"[red]File not found: {file}[/red]")
            raise typer.Exit(1)
        subdomains.extend(read_subdomains(src))

    # Allow piped stdin without -f flag
    if not subdomains and not sys.stdin.isatty():
        subdomains = read_subdomains("-")

    if not subdomains:
        console.print("[red]No subdomains provided. Use a domain argument, --file, or pipe from subfinder/amass.[/red]")
        console.print("[dim]Examples:[/dim]")
        console.print("  subzero scan scanme.example.org")
        console.print("  subzero scan -f subdomains.txt")
        console.print("  subfinder -d example.org -silent | subzero scan -")
        raise typer.Exit(1)

    subdomains = list(dict.fromkeys(s for s in subdomains if s))  # deduplicate
    console.print(f"  [bold]Targets[/bold]      : [cyan]{len(subdomains):,}[/cyan] subdomains")
    console.print(f"  [bold]Concurrency[/bold]  : {concurrency}")
    console.print(f"  [bold]Fingerprints[/bold] : {len(FINGERPRINTS)} services")
    console.print(f"  [bold]Validation[/bold]   : DNS (4 resolvers, 3/4 consensus) + HTTP (dual-attempt) + scoring\n")

    if not quiet:
        console.print("[dim]  Verdict   Subdomain                                     Service              Score  CNAME[/dim]")
        console.print("[dim]  " + "─" * 100 + "[/dim]")

    # Run async scan
    all_results = []
    stats = ScanStats()

    async def _run():
        async for result in scan_stream(
            subdomains,
            concurrency=concurrency,
            only_vulnerable=only_vulnerable,
            min_verdict=min_verdict,
            profile=profile,
        ):
            if explain and result.verdict != Verdict.SAFE:
                result.evidence_bundle["explain"] = build_explanation(result)
            if evidence_level == "min":
                result.evidence_bundle = {
                    "risk": result.evidence_bundle.get("risk", {}),
                    "verification": result.evidence_bundle.get("verification", {}),
                    "explain": result.evidence_bundle.get("explain"),
                }
            all_results.append(result)
            stats.total += 1
            match result.verdict:
                case Verdict.VULNERABLE:  stats.vulnerable  += 1
                case Verdict.POTENTIAL:   stats.potential   += 1
                case Verdict.INVESTIGATE: stats.investigate += 1
                case Verdict.SAFE:        stats.safe        += 1

            if not quiet:
                print_result_live(result)
                if explain and result.verdict != Verdict.SAFE:
                    console.print(f"[dim]    explain: {build_explanation(result)}[/dim]")

    asyncio.run(_run())

    print_summary_table(all_results)

    if output:
        suffix = output.suffix.lower()
        if suffix == ".json":
            export_json(all_results, output)
            console.print(f"\n[green]✓ JSON report saved: {output}[/green]")
        elif suffix in (".md", ".markdown"):
            export_markdown(all_results, output)
            console.print(f"\n[green]✓ Markdown report saved: {output}[/green]")
        else:
            # Default to JSON
            export_json(all_results, output)
            console.print(f"\n[green]✓ Saved: {output}[/green]")


# ── fingerprints ──────────────────────────────────────────────────────────────

@app.command("fingerprints", help="List or inspect the fingerprint database")
def cmd_fingerprints(
    show: Optional[str] = typer.Argument(
        None,
        help="Service name to show in detail (partial match, case-insensitive)",
    ),
):
    _banner()

    if show:
        matches = [fp for fp in FINGERPRINTS if show.lower() in fp.name.lower()]
        if not matches:
            console.print(f"[red]No fingerprints matching '{show}'[/red]")
            raise typer.Exit(1)
        for fp in matches:
            lines = [
                f"[bold]Name:[/bold]           {fp.name}",
                f"[bold]CNAME patterns:[/bold] {', '.join(fp.cname_patterns)}",
                f"[bold]NXDOMAIN:[/bold]       {fp.nxdomain}",
                f"[bold]Confidence CNAME:[/bold] {fp.confidence_cname}",
                f"[bold]Confidence body:[/bold]  {fp.confidence_body}",
                "",
                "[bold]HTTP fingerprints:[/bold]",
            ]
            for phrase in fp.http_fingerprints:
                lines.append(f"  - [yellow]{phrase}[/yellow]")
            lines += [
                "",
                f"[bold]How to take over:[/bold] {fp.takeover_info}",
            ]
            for ref in fp.references:
                lines.append(f"  [dim]{ref}[/dim]")
            console.print(Panel("\n".join(lines), title=f"[cyan]{fp.name}[/cyan]", expand=False))
        return

    from rich.table import Table
    table = Table(
        title=f"[bold]Fingerprint Database[/bold]  ({len(FINGERPRINTS)} services)",
        show_header=True, header_style="bold blue",
    )
    table.add_column("#",              width=4,  justify="right")
    table.add_column("Service",        style="cyan")
    table.add_column("CNAME patterns", style="dim", overflow="fold")
    table.add_column("Score CNAME",    width=12, justify="center")
    table.add_column("Score body",     width=10, justify="center")
    table.add_column("HTTP phrases",   width=5,  justify="center")

    for i, fp in enumerate(FINGERPRINTS, 1):
        table.add_row(
            str(i),
            fp.name,
            ", ".join(fp.cname_patterns),
            str(fp.confidence_cname),
            str(fp.confidence_body),
            str(len(fp.http_fingerprints)),
        )
    console.print(table)


# ── dns ──────────────────────────────────────────────────────────────────────

@app.command("dns", help="Run multi-resolver DNS analysis on a single subdomain")
def cmd_dns(
    subdomain: str = typer.Argument(..., help="Subdomain to analyse"),
):
    _banner()
    from subzero.dns_resolver import resolve as dns_resolve
    from rich.table import Table

    result = asyncio.run(dns_resolve(subdomain))

    table = Table(title=f"[bold]DNS Analysis: {subdomain}[/bold]", show_header=True, header_style="bold blue")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("CNAME chain",       " → ".join(result.cname_chain) or "(none)")
    table.add_row("Final CNAME",       result.final_cname or "(none)")
    table.add_row("A records",         ", ".join(result.a_records) or "(none)")
    table.add_row("AAAA records",      ", ".join(result.aaaa_records) or "(none)")
    table.add_row("NS records",        ", ".join(result.ns_records) or "(none)")
    table.add_row("SOA mname",         result.soa_mname or "(none)")
    table.add_row("Negative TTL",      str(result.negative_ttl) if result.negative_ttl is not None else "(none)")
    table.add_row("DNSSEC supported",  str(result.dnssec_supported))
    table.add_row("NXDOMAIN votes",    f"{result.nxdomain_votes}/4 resolvers")
    table.add_row("NXDOMAIN confirmed",str(result.nxdomain_confirmed))
    table.add_row("Dangling CNAME",    str(result.dangling_cname))
    table.add_row("NS delegation",     str(result.ns_delegation))
    console.print(table)

    if result.raw_resolver_responses:
        r_table = Table(title="[bold]Per-Resolver Detail[/bold]", show_header=True, header_style="bold blue")
        r_table.add_column("Resolver",  style="cyan")
        r_table.add_column("NXDOMAIN", justify="center")
        r_table.add_column("A records", style="dim")
        r_table.add_column("Error",     style="red dim")
        for name, detail in result.raw_resolver_responses.items():
            r_table.add_row(
                name,
                "[red]YES[/red]" if detail["nxdomain"] else "[green]NO[/green]",
                ", ".join(detail["records"]) or "-",
                detail.get("error") or "-",
            )
        console.print(r_table)


@app.command("verify", help="Run second-pass verification for one subdomain")
def cmd_verify(
    subdomain: Optional[str] = typer.Argument(None, help="Subdomain to verify"),
    force: bool = typer.Option(
        False, "--force",
        help="Run second-pass checks even when first-pass has no takeover indicators",
    ),
):
    _banner()
    if not subdomain:
        console.print("[red]Missing required input:[/red] SUBDOMAIN")
        console.print("\n[bold]Verify Examples[/bold]")
        console.print("1. subzero verify scanme.example.org")
        console.print("2. subzero verify api.example.org")
        raise typer.Exit(2)

    try:
        dns_result = asyncio.run(_bounded(dns_resolve(subdomain)))
        if dns_result.resolver_unreachable:
            http_result = HTTPResult(
                subdomain=subdomain,
                reachable=False,
                errors=["HTTP probe skipped: DNS resolvers unreachable"],
            )
        else:
            http_result = asyncio.run(_bounded(http_probe(subdomain)))
    except TimeoutError:
        console.print("[red]Verification timed out while collecting DNS/HTTP evidence.[/red]")
        console.print("[dim]Try again from a less restricted network or use --force with caution.[/dim]")
        raise typer.Exit(1)
    result = evaluate(dns_result, http_result)

    should_run_second_pass = force or result.verdict in (Verdict.VULNERABLE, Verdict.POTENTIAL, Verdict.INVESTIGATE)
    if not force and result.verdict == Verdict.SAFE and result.fingerprint is None:
        should_run_second_pass = False

    expected_status = result.fingerprint.status_codes if result.fingerprint else []
    expected_phrases = result.fingerprint.http_fingerprints if result.fingerprint else []
    if should_run_second_pass:
        try:
            verification = asyncio.run(
                _bounded(verify_candidate(
                    subdomain=subdomain,
                    nxdomain_target=dns_result.final_cname or subdomain,
                    expected_status_codes=expected_status,
                    expected_phrases=expected_phrases,
                ))
            )
        except TimeoutError:
            from subzero.verifier import VerificationResult, VerificationEvidence
            verification = VerificationResult(
                confirmed=False,
                score=0,
                evidence=VerificationEvidence(
                    notes=["Second-pass verification timed out."],
                ),
            )
    else:
        from subzero.verifier import VerificationResult, VerificationEvidence
        verification = VerificationResult(
            confirmed=False,
            score=0,
            evidence=VerificationEvidence(
                notes=["Second-pass skipped: no takeover indicators in first-pass verdict."],
            ),
        )

    from rich.table import Table
    table = Table(title=f"[bold]Verification: {subdomain}[/bold]", show_header=True, header_style="bold blue")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Initial verdict", result.verdict.value)
    table.add_row("Initial confidence", str(result.confidence))
    table.add_row("Verification confirmed", str(verification.confirmed))
    table.add_row("Verification score", str(verification.score))
    table.add_row("dig CNAME", ", ".join(verification.evidence.dig_cname) or "(none)")
    table.add_row("NXDOMAIN target", verification.evidence.nxdomain_target or "-")
    table.add_row("NXDOMAIN votes (2 resolvers)", str(verification.evidence.nxdomain_votes_two_resolvers))
    table.add_row("curl-style HTTP status", str(verification.evidence.curl_http_status or "-"))
    console.print(table)

    if verification.evidence.notes:
        console.print("\n[bold]Evidence Notes[/bold]")
        for note in verification.evidence.notes:
            console.print(f"- {note}")


@app.command("enumerate", help="Passive subdomain enumeration from public sources")
def cmd_enumerate(
    domain: Optional[str] = typer.Argument(None, help="Root domain, e.g. example.org"),
    sources: str = typer.Option("crtsh,hackertarget", "--sources", help="Comma list: crtsh,hackertarget,shodan,censys,fofa"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save subdomains list"),
    config: Optional[Path] = typer.Option(None, "--config", help="Path to subzero.yaml"),
):
    _banner()
    cfg = load_config(config)
    if not domain:
        console.print("[red]Missing required input:[/red] DOMAIN")
        console.print("\n[bold]Enumerate Examples[/bold]")
        console.print("1. subzero enumerate example.org")
        console.print("2. subzero enumerate example.org --sources crtsh,hackertarget -o passive.txt")
        raise typer.Exit(2)

    if sources == "crtsh,hackertarget" and cfg.enumerate.sources:
        src_list = [s.strip().lower() for s in cfg.enumerate.sources if s.strip()]
    else:
        src_list = [s.strip().lower() for s in sources.split(",") if s.strip()]
    allowed_sources = {"crtsh", "hackertarget", "shodan", "censys", "fofa"}
    unknown = [s for s in src_list if s not in allowed_sources]
    if unknown:
        console.print(f"[red]Invalid --sources entries:[/red] {', '.join(unknown)}")
        console.print("[dim]Allowed sources: crtsh, hackertarget, shodan, censys, fofa[/dim]")
        console.print("[dim]Example: subzero enumerate example.org --sources crtsh,hackertarget,shodan[/dim]")
        raise typer.Exit(2)

    data = asyncio.run(enumerate_passive(domain, src_list))
    merged = sorted({x for vals in data.values() for x in vals})

    console.print(f"[bold]Domain:[/bold] {domain}")
    for src in src_list:
        console.print(f"[bold]{src}:[/bold] {len(data.get(src, []))} entries")
    console.print(f"[bold]Total unique:[/bold] {len(merged)}")
    for sub in merged[:50]:
        console.print(sub)
    if len(merged) > 50:
        console.print(f"[dim]... and {len(merged)-50} more[/dim]")

    if output:
        output.write_text("\\n".join(merged) + "\\n")
        console.print(f"[green]✓ Saved: {output}[/green]")


@app.command("feedback", help="Record TP/FP labels and recalibrate fingerprint weights")
def cmd_feedback(
    subdomain: Optional[str] = typer.Argument(None, help="Subdomain label target"),
    service: Optional[str] = typer.Option(None, "--service", help="Fingerprint service name"),
    verdict: Optional[str] = typer.Option(None, "--verdict", help="Scanner verdict"),
    label: Optional[str] = typer.Option(None, "--label", help="tp or fp"),
):
    _banner()
    missing: list[str] = []
    if not subdomain:
        missing.append("SUBDOMAIN")
    if not service:
        missing.append("--service")
    if not verdict:
        missing.append("--verdict")
    if not label:
        missing.append("--label")

    if missing:
        console.print(f"[red]Missing required input:[/red] {', '.join(missing)}")
        console.print("\n[bold]Feedback Parameters[/bold]")
        console.print("- `SUBDOMAIN` : target hostname (e.g. `scanme.example.org`)")
        console.print("- `--service` : matched fingerprint service name (e.g. `Amazon S3`)")
        console.print("- `--verdict` : scanner verdict (`VULNERABLE`, `POTENTIAL`, `INVESTIGATE`, `SAFE`)")
        console.print("- `--label`   : analyst ground truth (`tp` or `fp`)")
        console.print("\n[bold]Examples[/bold]")
        console.print("1. subzero feedback scanme.example.org --service \"Amazon S3\" --verdict VULNERABLE --label tp")
        console.print("2. subzero feedback scanme.example.org --service Netlify --verdict POTENTIAL --label fp")
        raise typer.Exit(2)

    verdict = verdict.upper().strip()
    if verdict not in {"VULNERABLE", "POTENTIAL", "INVESTIGATE", "SAFE"}:
        console.print(f"[red]Invalid --verdict:[/red] {verdict}")
        console.print("[dim]Allowed: VULNERABLE, POTENTIAL, INVESTIGATE, SAFE[/dim]")
        raise typer.Exit(2)

    label = label.lower().strip()
    if label not in {"tp", "fp"}:
        console.print(f"[red]Invalid --label:[/red] {label}")
        console.print("[dim]Allowed: tp, fp[/dim]")
        raise typer.Exit(2)

    record_label(subdomain=subdomain, service=service, verdict=verdict, label=label)
    cal = recompute_calibration()
    console.print(f"[green]✓ Feedback recorded[/green]")
    if service in cal:
        console.print(
            f"[bold]{service} calibration:[/bold] cname_delta={cal[service].cname_delta}, body_delta={cal[service].body_delta}"
        )


if __name__ == "__main__":
    app()
