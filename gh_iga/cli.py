"""CLI entry point for gh-iga."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click
import requests
from rich.console import Console

from . import __version__
from .rules import generate_findings
from .scanner import scan_org

console = Console()
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# CLI root
# ---------------------------------------------------------------------------


@click.group()
@click.version_option(__version__, prog_name="gh-iga")
def main() -> None:
    """gh-iga — Identity governance scanner for GitHub orgs.

    Run 'gh-iga scan --help' to get started.
    """


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------


@main.command()
@click.option(
    "--org",
    "-o",
    required=True,
    help="GitHub org login to scan (e.g. 'mycompany').",
)
@click.option(
    "--token",
    "-t",
    default=lambda: os.environ.get("GITHUB_TOKEN", ""),
    show_default="$GITHUB_TOKEN",
    help="GitHub Personal Access Token. Reads $GITHUB_TOKEN if not set.",
)
@click.option(
    "--output-dir",
    "-d",
    default=".",
    show_default=True,
    type=click.Path(file_okay=False, writable=True),
    help="Directory to write report files.",
)
@click.option(
    "--format",
    "fmt",
    default="all",
    show_default=True,
    type=click.Choice(["all", "html", "md", "json"], case_sensitive=False),
    help="Output format(s) to produce.",
)
@click.option(
    "--inactive-days",
    default=90,
    show_default=True,
    help="Days of inactivity before flagging a privileged user.",
)
@click.option(
    "--admin-sprawl-threshold",
    default=5,
    show_default=True,
    help="Flag users with admin access to this many or more repos.",
)
@click.option(
    "--max-admins-per-repo",
    default=3,
    show_default=True,
    help="Flag repos with more than this many admins.",
)
@click.option(
    "--no-activity",
    is_flag=True,
    default=False,
    help="Skip activity checks (faster, but disables the inactive-user rule).",
)
@click.option(
    "--no-html",
    is_flag=True,
    default=False,
    help="Do not produce an HTML report.",
)
@click.option(
    "--no-json",
    is_flag=True,
    default=False,
    help="Do not produce a JSON output file.",
)
def scan(
    org: str,
    token: str,
    output_dir: str,
    fmt: str,
    inactive_days: int,
    admin_sprawl_threshold: int,
    max_admins_per_repo: int,
    no_activity: bool,
    no_html: bool,
    no_json: bool,
) -> None:
    """Scan a GitHub org and produce an access governance report."""

    # ------------------------------------------------------------------
    # Pre-flight checks
    # ------------------------------------------------------------------
    if not token:
        err_console.print(
            "[bold red]Error:[/bold red] No GitHub token found.\n"
            "Set the [bold]GITHUB_TOKEN[/bold] environment variable "
            "or pass [bold]--token[/bold].\n\n"
            "Token needs scopes: [cyan]read:org[/cyan], [cyan]repo[/cyan]"
        )
        sys.exit(1)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Determine which formats to produce
    want_html = fmt in ("all", "html") and not no_html
    want_md = fmt in ("all", "md")
    want_json = fmt in ("all", "json") and not no_json

    # ------------------------------------------------------------------
    # Banner
    # ------------------------------------------------------------------
    console.print()
    console.rule("[bold blue]gh-iga — Identity Governance Scanner for GitHub[/bold blue]")
    console.print(f"  [dim]Org:[/dim]  [bold]{org}[/bold]")
    console.print(f"  [dim]v{__version__}[/dim]")
    console.print()

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------
    try:
        result = scan_org(
            org,
            token,
            inactive_days=inactive_days,
            check_activity=not no_activity,
            console=console,
        )
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        if status == 401:
            err_console.print("[bold red]Auth error (401):[/bold red] Token is invalid or expired.")
        elif status == 403:
            err_console.print(
                "[bold red]Forbidden (403):[/bold red] Token lacks required scopes "
                "([cyan]read:org[/cyan], [cyan]repo[/cyan])."
            )
        elif status == 404:
            err_console.print(
                f"[bold red]Not found (404):[/bold red] Org '[bold]{org}[/bold]' does not exist "
                "or is not accessible with this token."
            )
        else:
            err_console.print(f"[bold red]GitHub API error ({status}):[/bold red] {exc}")
        sys.exit(1)
    except Exception as exc:
        err_console.print(f"[bold red]Unexpected error:[/bold red] {exc}")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Run findings rules
    # ------------------------------------------------------------------
    result.findings = generate_findings(
        result,
        inactive_days=inactive_days,
        admin_sprawl_threshold=admin_sprawl_threshold,
        max_admins_per_repo=max_admins_per_repo,
    )

    # ------------------------------------------------------------------
    # Write reports (before the terminal summary, so a rendering failure
    # on limited consoles never loses the report files)
    # ------------------------------------------------------------------
    from .reports.terminal import print_summary, unicode_safe

    arrow = "→" if unicode_safe(console) else "->"
    timestamp = result.scanned_at.strftime("%Y%m%d-%H%M%S")
    stem = f"gh-iga-{org}-{timestamp}"
    written: list[str] = []

    if want_html:
        from .reports.html import write_html_report

        html_path = output_path / f"{stem}.html"
        write_html_report(result, html_path)
        written.append(f"HTML  {arrow} [cyan]{html_path}[/cyan]")

    if want_md:
        from .reports.markdown import write_markdown_report

        md_path = output_path / f"{stem}.md"
        write_markdown_report(result, md_path)
        written.append(f"MD    {arrow} [cyan]{md_path}[/cyan]")

    if want_json:
        from .reports.json_report import write_json_report

        json_path = output_path / f"{stem}.json"
        write_json_report(result, json_path)
        written.append(f"JSON  {arrow} [cyan]{json_path}[/cyan]")

    # ------------------------------------------------------------------
    # Terminal summary
    # ------------------------------------------------------------------
    try:
        print_summary(result, console=console)
    except Exception as exc:  # rendering is cosmetic — never abort the scan
        click.echo(f"warning: could not render terminal summary ({exc})", err=True)

    if written:
        console.print()
        console.rule("[dim]Reports[/dim]")
        for line in written:
            console.print(f"  {line}")
        console.print()


@main.command("scan-user")
@click.option(
    "--token",
    "-t",
    default=lambda: os.environ.get("GITHUB_TOKEN", ""),
    show_default="$GITHUB_TOKEN",
    help="GitHub Personal Access Token (needs 'repo' scope).",
)
@click.option(
    "--output-dir",
    "-d",
    default=".",
    show_default=True,
    type=click.Path(file_okay=False, writable=True),
    help="Directory to write report files.",
)
@click.option(
    "--format",
    "fmt",
    default="all",
    show_default=True,
    type=click.Choice(["all", "html", "md", "json"], case_sensitive=False),
    help="Output format(s) to produce.",
)
@click.option(
    "--no-html",
    is_flag=True,
    default=False,
    help="Do not produce an HTML report.",
)
@click.option(
    "--no-json",
    is_flag=True,
    default=False,
    help="Do not produce a JSON output file.",
)
def scan_user(token: str, output_dir: str, fmt: str, no_html: bool, no_json: bool) -> None:
    """Scan all repos on your personal GitHub account.

    No org needed — just a token with the 'repo' scope.
    """
    if not token:
        err_console.print(
            "[bold red]Error:[/bold red] No GitHub token found.\n"
            "Set [bold]GITHUB_TOKEN[/bold] or pass [bold]--token[/bold].\n"
            "Token needs scope: [cyan]repo[/cyan]"
        )
        sys.exit(1)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    want_html = fmt in ("all", "html") and not no_html
    want_md = fmt in ("all", "md")
    want_json = fmt in ("all", "json") and not no_json

    console.print()
    console.rule("[bold blue]gh-iga — Personal Repo Scanner[/bold blue]")
    console.print()

    try:
        from .scanner import scan_user as _scan_user

        result = _scan_user(token, console=console)
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        if status == 401:
            err_console.print("[bold red]Auth error (401):[/bold red] Token is invalid or expired.")
        else:
            err_console.print(f"[bold red]GitHub API error ({status}):[/bold red] {exc}")
        sys.exit(1)
    except Exception as exc:
        err_console.print(f"[bold red]Unexpected error:[/bold red] {exc}")
        sys.exit(1)

    # Run user-specific rules
    from .rules import generate_user_findings

    result.findings = generate_user_findings(result)

    # Write reports before the terminal summary, so a rendering failure
    # on limited consoles never loses the report files.
    from .reports.terminal import print_user_summary, unicode_safe

    arrow = "→" if unicode_safe(console) else "->"
    timestamp = result.scanned_at.strftime("%Y%m%d-%H%M%S")
    stem = f"gh-iga-user-{result.org}-{timestamp}"
    written: list[str] = []

    if want_html:
        from .reports.html import write_html_report

        html_path = output_path / f"{stem}.html"
        write_html_report(result, html_path)
        written.append(f"HTML  {arrow} [cyan]{html_path}[/cyan]")

    if want_md:
        from .reports.markdown import write_markdown_report

        md_path = output_path / f"{stem}.md"
        write_markdown_report(result, md_path)
        written.append(f"MD    {arrow} [cyan]{md_path}[/cyan]")

    if want_json:
        from .reports.json_report import write_json_report

        json_path = output_path / f"{stem}.json"
        write_json_report(result, json_path)
        written.append(f"JSON  {arrow} [cyan]{json_path}[/cyan]")

    try:
        print_user_summary(result, console=console)
    except Exception as exc:  # rendering is cosmetic — never abort the scan
        click.echo(f"warning: could not render terminal summary ({exc})", err=True)

    if written:
        console.print()
        console.rule("[dim]Reports[/dim]")
        for line in written:
            console.print(f"  {line}")
        console.print()


if __name__ == "__main__":
    main()
