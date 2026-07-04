"""
SOC Toolkit CLI
===============
Usage:
    soc-toolkit enrich <ioc> [<ioc> ...]
    soc-toolkit phishing <path/to/email.eml>
    soc-toolkit yara-scan <path/to/file-or-dir> [--rules <path>]
    soc-toolkit dashboard
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from soc_toolkit.core import enrichment, phishing, report, yara_scan

console = Console()


@click.group()
@click.version_option()
def cli():
    """SOC Toolkit — an all-in-one Python automation toolkit for SOC/security analysts."""
    pass


# ---------------------------------------------------------------------------
# enrich
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("iocs", nargs=-1, required=True)
@click.option("--format", "fmt", type=click.Choice(["table", "json", "html"]), default="table")
@click.option("--save", is_flag=True, help="Also write a report file to ./reports/")
def enrich(iocs, fmt, save):
    """Enrich one or more IOCs (IP, domain, URL, or hash) across threat-intel sources."""
    results = enrichment.enrich_bulk(list(iocs))

    if fmt == "json":
        click.echo(json.dumps(results, indent=2, default=str))
    elif fmt == "html":
        for r in results:
            path = report.generate_report(r, "enrichment", fmt="html")
            console.print(f"[green]HTML report saved:[/green] {path}")
    else:
        table = Table(title="IOC Enrichment Results")
        table.add_column("IOC")
        table.add_column("Type")
        table.add_column("Verdict")
        table.add_column("Risk Score")
        table.add_column("Sources Checked")
        for r in results:
            verdict_color = {
                "malicious": "red", "suspicious": "yellow", "clean": "green",
            }.get(r["verdict"], "white")
            table.add_row(
                r["ioc"], r["type"],
                f"[{verdict_color}]{r['verdict']}[/{verdict_color}]",
                str(r["risk_score"]),
                ", ".join(s["source"] for s in r["sources"]) or "-",
            )
        console.print(table)

    if save and fmt != "html":
        for r in results:
            path = report.generate_report(r, "enrichment", fmt="both")
            console.print(f"[dim]Saved report(s) for {r['ioc']}: {path}[/dim]")


# ---------------------------------------------------------------------------
# phishing
# ---------------------------------------------------------------------------

@cli.command(name="phishing")
@click.argument("eml_path", type=click.Path(exists=True))
@click.option("--enrich-iocs", is_flag=True, help="Also run enrichment on extracted IOCs")
@click.option("--format", "fmt", type=click.Choice(["summary", "json", "html"]), default="summary")
def phishing_cmd(eml_path, enrich_iocs, fmt):
    """Triage a raw .eml phishing submission."""
    result = phishing.triage_email(eml_path)

    if enrich_iocs and result["extracted_iocs"]:
        console.print(f"[dim]Enriching {len(result['extracted_iocs'])} extracted IOC(s)...[/dim]")
        result["ioc_enrichment"] = enrichment.enrich_bulk(result["extracted_iocs"])

    if fmt == "json":
        click.echo(json.dumps(result, indent=2, default=str))
        return
    if fmt == "html":
        path = report.generate_report(result, "phishing", fmt="html")
        console.print(f"[green]HTML report saved:[/green] {path}")
        return

    verdict_color = {"phishing": "red", "suspicious": "yellow", "likely benign": "green"}.get(result["verdict"], "white")
    console.print(f"\n[bold]File:[/bold] {result['file']}")
    console.print(f"[bold]Verdict:[/bold] [{verdict_color}]{result['verdict']}[/{verdict_color}]  (score: {result['score']}/100)")
    console.print(f"[bold]From:[/bold] {result['headers']['from']}")
    console.print(f"[bold]Subject:[/bold] {result['headers']['subject']}")
    if result["reasons"]:
        console.print("\n[bold]Reasons:[/bold]")
        for r in result["reasons"]:
            console.print(f"  - {r}")
    if result["extracted_iocs"]:
        console.print(f"\n[bold]Extracted IOCs ({len(result['extracted_iocs'])}):[/bold]")
        for i in result["extracted_iocs"]:
            console.print(f"  - {i}")


# ---------------------------------------------------------------------------
# yara-scan
# ---------------------------------------------------------------------------

@cli.command(name="yara-scan")
@click.argument("target_path", type=click.Path(exists=True))
@click.option("--rules", "rules_path", type=click.Path(exists=True), default=None, help="Custom rules file/dir")
@click.option("--format", "fmt", type=click.Choice(["summary", "json", "html"]), default="summary")
def yara_scan_cmd(target_path, rules_path, fmt):
    """Scan a file or directory against YARA detection rules."""
    result = yara_scan.scan(target_path, rules_path)

    if fmt == "json":
        click.echo(json.dumps(result, indent=2, default=str))
        return
    if fmt == "html":
        path = report.generate_report(result, "yara", fmt="html")
        console.print(f"[green]HTML report saved:[/green] {path}")
        return

    console.print(f"\n[bold]Scanned:[/bold] {result['scanned_path']}")
    console.print(f"[bold]Files scanned:[/bold] {result['total_files']}")
    match_color = "red" if result["matches_found"] else "green"
    console.print(f"[bold]Matches found:[/bold] [{match_color}]{result['matches_found']}[/{match_color}]\n")

    for r in result["results"]:
        if r["status"] == "match":
            console.print(f"[red bold]MATCH[/red bold] {r['file']}")
            for m in r["matches"]:
                console.print(f"    rule: {m['rule']}  tags: {', '.join(m['tags'])}")


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--port", default=8501, help="Port to run the Streamlit dashboard on")
def dashboard(port):
    """Launch the web dashboard (Streamlit)."""
    app_path = Path(__file__).parent / "dashboard" / "app.py"
    console.print(f"[green]Launching dashboard on http://localhost:{port}[/green]")
    subprocess.run([sys.executable, "-m", "streamlit", "run", str(app_path), "--server.port", str(port)])


@cli.command()
def cache_clear():
    """Clear the local enrichment cache."""
    from soc_toolkit.utils import cache
    n = cache.clear()
    console.print(f"[green]Cleared {n} cached entries.[/green]")


def main():
    cli()


if __name__ == "__main__":
    main()
