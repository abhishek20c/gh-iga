"""Tests for terminal rendering on consoles that can't encode unicode glyphs.

Legacy Windows consoles (cp1252) raise UnicodeEncodeError on characters like
'⚠'. The terminal report must fall back to ASCII icons there, and the CLI must
write report files even if summary rendering fails.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone

from click.testing import CliRunner
from rich.console import Console

import gh_iga.cli as cli_mod
import gh_iga.reports.terminal as terminal
from gh_iga.models import Finding, Member, ScanResult, Severity
from gh_iga.reports.terminal import print_summary, print_user_summary, unicode_safe


def _result(*findings: Finding) -> ScanResult:
    return ScanResult(
        org="acme",
        scanned_at=datetime.now(timezone.utc),
        members=[Member("alice", None, "owner")],
        outside_collaborators=[],
        repos=[],
        teams=[],
        findings=list(findings),
    )


def _findings() -> list[Finding]:
    return [
        Finding(Severity.HIGH, "cat_high", "High risk", "detail", affected=["a"]),
        Finding(Severity.MEDIUM, "cat_med", "Medium risk", "detail",
                affected=[f"repo-{i}" for i in range(8)]),  # exercises truncation ellipsis
        Finding(Severity.LOW, "cat_low", "Low risk", "detail"),
    ]


def _cp1252_console() -> tuple[Console, io.BytesIO]:
    """A console whose stream, like a legacy Windows terminal, is cp1252."""
    buffer = io.BytesIO()
    stream = io.TextIOWrapper(buffer, encoding="cp1252")
    return Console(file=stream, width=100, legacy_windows=False), buffer


# ---------------------------------------------------------------------------
# Encoding detection
# ---------------------------------------------------------------------------


def test_unicode_safe_true_for_utf8():
    assert unicode_safe(Console(file=io.StringIO(), width=100, legacy_windows=False))


def test_unicode_safe_false_for_cp1252():
    console, _ = _cp1252_console()
    assert not unicode_safe(console)


def test_unicode_safe_false_for_legacy_windows():
    assert not unicode_safe(Console(file=io.StringIO(), width=100, legacy_windows=True))


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def test_print_summary_cp1252_does_not_crash_and_uses_ascii_icons():
    console, buffer = _cp1252_console()
    print_summary(_result(*_findings()), console=console)  # must not raise
    console.file.flush()
    output = buffer.getvalue().decode("cp1252")
    assert "!" in output           # MEDIUM fallback icon
    assert "x" in output           # HIGH fallback icon
    assert "... and 3 more" in output
    assert "⚠" not in output


def test_print_summary_cp1252_no_findings_does_not_crash():
    console, buffer = _cp1252_console()
    print_summary(_result(), console=console)
    console.file.flush()
    assert "No governance issues found." in buffer.getvalue().decode("cp1252")


def test_print_summary_utf8_keeps_unicode_icons():
    stream = io.StringIO()
    console = Console(file=stream, width=100, legacy_windows=False)
    print_summary(_result(*_findings()), console=console)
    output = stream.getvalue()
    assert "⚠" in output
    assert "✗" in output
    assert "… and 3 more" in output


def test_print_user_summary_cp1252_does_not_crash():
    console, buffer = _cp1252_console()
    print_user_summary(_result(*_findings()), console=console)
    console.file.flush()
    output = buffer.getvalue().decode("cp1252")
    assert "!" in output
    assert "⚠" not in output


# ---------------------------------------------------------------------------
# CLI: reports survive a summary-rendering failure
# ---------------------------------------------------------------------------


def test_reports_written_even_if_summary_rendering_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(cli_mod, "scan_org", lambda *a, **k: _result())
    monkeypatch.setattr(cli_mod, "generate_findings", lambda *a, **k: [])

    def boom(*args, **kwargs):
        raise UnicodeEncodeError("charmap", "⚠", 0, 1, "character maps to <undefined>")

    monkeypatch.setattr(terminal, "print_summary", boom)

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.main,
        ["scan", "--org", "acme", "--token", "t", "--output-dir", str(tmp_path)],
    )

    assert result.exit_code == 0, result.output
    assert list(tmp_path.glob("gh-iga-acme-*.html"))
    assert list(tmp_path.glob("gh-iga-acme-*.md"))
    assert list(tmp_path.glob("gh-iga-acme-*.json"))
