"""HTML report writer — self-contained single-file report via Jinja2."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import __version__
from ..models import ScanResult

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def write_html_report(result: ScanResult, path: Path) -> None:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["perm_color"] = _perm_color
    env.filters["severity_color"] = _severity_color

    template = env.get_template("report.html.j2")
    html = template.render(result=result, version=__version__)
    path.write_text(html, encoding="utf-8")


def _perm_color(permission: str) -> str:
    return {
        "admin": "#e53e3e",
        "maintain": "#dd6b20",
        "write": "#d69e2e",
        "triage": "#3182ce",
        "read": "#718096",
    }.get(permission, "#718096")


def _severity_color(severity: str) -> str:
    return {
        "high": "#e53e3e",
        "medium": "#d69e2e",
        "low": "#3182ce",
    }.get(severity, "#718096")
