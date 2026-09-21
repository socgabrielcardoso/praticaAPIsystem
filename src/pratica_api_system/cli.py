from __future__ import annotations

import asyncio
import json
from typing import Annotated

import typer
import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .config import get_settings
from .indicators import IndicatorValidationError
from .models import AnalysisResult
from .service import ThreatIntelService

app = typer.Typer(
    name="pratica-api",
    help="Blue team enrichment for IPs, domains, URLs, hashes and CVEs.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def analyze(
    indicator: Annotated[str, typer.Argument(help="Indicator to enrich")],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print machine readable JSON"),
    ] = False,
) -> None:
    """Analyze one defensive indicator across configured intelligence providers."""
    try:
        result = asyncio.run(_analyze(indicator))
    except IndicatorValidationError as exc:
        console.print(f"[red]Invalid indicator:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if json_output:
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2, ensure_ascii=False))
        return
    _render_result(result)


@app.command()
def providers() -> None:
    """Show which intelligence providers are ready to query."""
    asyncio.run(_render_providers())


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Bind address")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="TCP port", min=1, max=65535)] = 8080,
) -> None:
    """Start the local enrichment API."""
    uvicorn.run("pratica_api_system.api:app", host=host, port=port, reload=False)


async def _analyze(indicator: str) -> AnalysisResult:
    settings = get_settings()
    async with ThreatIntelService(settings) as service:
        return await service.analyze(indicator)


async def _render_providers() -> None:
    settings = get_settings()
    async with ThreatIntelService(settings) as service:
        table = Table(title="Intelligence providers")
        table.add_column("Provider")
        table.add_column("Ready")
        table.add_column("Indicators")
        table.add_column("Note")
        for state in service.provider_states():
            table.add_row(
                state.name,
                "yes" if state.configured else "no",
                ", ".join(item.value for item in state.supported_types),
                state.reason or "",
            )
        console.print(table)


def _render_result(result: AnalysisResult) -> None:
    header = (
        f"[bold]{result.indicator.normalized}[/bold]\n"
        f"type={result.indicator.type.value}  "
        f"verdict={result.verdict.value}  score={result.score}/100"
    )
    console.print(Panel(header, title="praticaAPIsystem", border_style="cyan"))

    table = Table(show_header=True)
    table.add_column("Provider")
    table.add_column("Verdict")
    table.add_column("Score", justify="right")
    table.add_column("Summary")
    for finding in result.findings:
        table.add_row(
            finding.provider,
            finding.verdict.value,
            str(finding.score),
            finding.summary,
        )
    if result.findings:
        console.print(table)
    else:
        console.print("[yellow]No provider returned a finding.[/yellow]")

    if result.skipped_providers:
        console.print(f"[dim]Skipped: {', '.join(result.skipped_providers)}[/dim]")
    if result.errors:
        for error in result.errors:
            console.print(f"[red]{error.provider}:[/red] {error.message}")
    console.print(f"[dim]Completed in {result.duration_ms} ms[/dim]")
