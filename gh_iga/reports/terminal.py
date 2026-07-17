"""Rich terminal summary output."""

from __future__ import annotations

from rich.console import Console
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from ..models import ScanResult, Severity

_SEVERITY_STYLE = {
    Severity.HIGH:   "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW:    "dim cyan",
}

_SEVERITY_ICON = {
    Severity.HIGH:   "✗",
    Severity.MEDIUM: "⚠",
    Severity.LOW:    "·",
}

_SEVERITY_ICON_ASCII = {
    Severity.HIGH:   "x",
    Severity.MEDIUM: "!",
    Severity.LOW:    "-",
}


def unicode_safe(console: Console) -> bool:
    """Whether the console can render non-ASCII glyphs like ⚠.

    Legacy Windows consoles (cp1252 etc.) raise UnicodeEncodeError on them.
    """
    return not (console.legacy_windows or console.options.ascii_only)


def _glyphs(console: Console) -> tuple[dict[str, str], str, str]:
    """Return (severity icons, ellipsis, info icon) safe for this console."""
    if unicode_safe(console):
        return _SEVERITY_ICON, "…", "ℹ"
    return _SEVERITY_ICON_ASCII, "...", "i"


def _print_coverage(result: ScanResult, console: Console) -> None:
    if not result.incomplete_coverage:
        return

    lines = [
        "[bold yellow]Partial scan:[/bold yellow] some optional inventories "
        "could not be inspected."
    ]
    for coverage in result.incomplete_coverage:
        scopes = ", ".join(issue.scope for issue in coverage.issues[:5])
        remaining = coverage.skipped - min(coverage.skipped, 5)
        if remaining:
            scopes += f", and {remaining} more"
        lines.append(
            f"[dim]{coverage.label}: {coverage.succeeded}/{coverage.attempted} "
            f"scopes inspected; skipped {scopes}.[/dim]"
        )
    console.print(Panel("\n".join(lines), border_style="yellow", title="Scan Coverage"))


def print_summary(result: ScanResult, *, console: Console | None = None) -> None:
    if console is None:
        console = Console()

    icons, ellipsis, info = _glyphs(console)

    console.print()
    console.rule("[bold blue]Scan Results[/bold blue]")

    # ------------------------------------------------------------------
    # Stats row
    # ------------------------------------------------------------------
    stats = Table.grid(padding=(0, 3))
    stats.add_column(justify="right", style="dim")
    stats.add_column(justify="left", style="bold")

    stats.add_row("Org",     result.org)
    stats.add_row("Members", str(len(result.members)))
    stats.add_row("Repos",   f"{len(result.active_repos)} active / {len(result.repos)} total")
    stats.add_row("Teams",   str(len(result.teams)))
    stats.add_row(
        "Outside collabs",
        str(len(result.outside_collaborators)),
    )
    stats.add_row("Installed apps", str(len(result.installed_apps)))
    stats.add_row("Deploy keys", str(len(result.deploy_keys)))
    stats.add_row("Actions secrets", str(len(result.actions_secrets)))
    stats.add_row("Webhooks", str(len(result.webhooks)))
    stats.add_row("Workflow permissions", str(len(result.workflow_permissions)))
    stats.add_row("Scan status", result.scan_status)
    stats.add_row(
        "Scanned at",
        result.scanned_at.strftime("%Y-%m-%d %H:%M UTC"),
    )

    console.print(Padding(stats, (1, 4)))
    _print_coverage(result, console)

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------
    if not result.findings:
        console.print(
            Panel(
                "[bold green]No governance issues found.[/bold green]\n"
                "[dim]Great posture — re-run periodically to stay clean.[/dim]",
                border_style="green",
            )
        )
        return

    console.print()
    console.rule("[bold]Risk Findings[/bold]")
    console.print()

    for finding in result.findings:
        style = _SEVERITY_STYLE[finding.severity]
        icon  = icons[finding.severity]

        console.print(
            f"  [{style}]{icon}[/{style}]  "
            f"[{style}]{finding.title}[/{style}]"
        )

        # Show up to 5 affected items inline; truncate the rest
        if finding.affected:
            shown = finding.affected[:5]
            rest  = len(finding.affected) - len(shown)
            items = ", ".join(shown)
            if rest > 0:
                items += f" [dim]{ellipsis} and {rest} more[/dim]"
            console.print(f"       [dim]{items}[/dim]")

        console.print()

    # ------------------------------------------------------------------
    # Totals footer
    # ------------------------------------------------------------------
    totals = Table.grid(padding=(0, 2))
    totals.add_column(justify="right", style="dim")
    totals.add_column(justify="left")

    h = len(result.high_findings)
    m = len(result.medium_findings)
    lo = len(result.low_findings)

    totals.add_row("High",   f"[bold red]{h}[/bold red]")
    totals.add_row("Medium", f"[bold yellow]{m}[/bold yellow]")
    totals.add_row("Low",    f"[dim cyan]{lo}[/dim cyan]")

    console.print(
        Panel(
            totals,
            title="[bold]Finding Totals[/bold]",
            border_style="dim",
            expand=False,
        )
    )
    console.print()

    if not result.activity_checked:
        console.print(
            f"  [dim]{info}  Activity checks skipped (--no-activity). "
            "The inactive-user rule was not evaluated.[/dim]\n"
        )


def print_user_summary(result: ScanResult, *, console: Console | None = None) -> None:
    """Terminal summary for a personal account scan."""
    if console is None:
        console = Console()

    icons, ellipsis, _ = _glyphs(console)

    console.print()
    console.rule("[bold blue]Scan Results[/bold blue]")

    stats = Table.grid(padding=(0, 3))
    stats.add_column(justify="right", style="dim")
    stats.add_column(justify="left", style="bold")
    stats.add_row("Account",      result.org)
    stats.add_row("Repos",        f"{len(result.active_repos)} active / {len(result.repos)} total")
    stats.add_row("Collaborators", str(len(result.outside_collaborators)))
    stats.add_row("Deploy keys",  str(len(result.deploy_keys)))
    stats.add_row("Actions secrets", str(len(result.actions_secrets)))
    stats.add_row("Webhooks",     str(len(result.webhooks)))
    stats.add_row("Workflow permissions", str(len(result.workflow_permissions)))
    stats.add_row("Scan status", result.scan_status)
    stats.add_row("Scanned at",   result.scanned_at.strftime("%Y-%m-%d %H:%M UTC"))
    console.print(Padding(stats, (1, 4)))
    _print_coverage(result, console)

    if not result.findings:
        console.print(
            Panel("[bold green]No issues found.[/bold green]", border_style="green")
        )
        return

    console.print()
    console.rule("[bold]Risk Findings[/bold]")
    console.print()

    for finding in result.findings:
        style = _SEVERITY_STYLE[finding.severity]
        icon  = icons[finding.severity]
        console.print(f"  [{style}]{icon}[/{style}]  [{style}]{finding.title}[/{style}]")
        if finding.affected:
            shown = finding.affected[:5]
            rest  = len(finding.affected) - len(shown)
            items = ", ".join(shown)
            if rest > 0:
                items += f" [dim]{ellipsis} and {rest} more[/dim]"
            console.print(f"       [dim]{items}[/dim]")
        console.print()
