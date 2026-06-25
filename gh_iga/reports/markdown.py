"""Markdown report writer."""

from __future__ import annotations

from pathlib import Path

from .. import __version__
from ..models import ScanResult, Severity

_SEVERITY_BADGE = {
    Severity.HIGH:   "🔴 HIGH",
    Severity.MEDIUM: "🟡 MEDIUM",
    Severity.LOW:    "🔵 LOW",
}


def write_markdown_report(result: ScanResult, path: Path) -> None:
    lines: list[str] = []
    a = lines.append  # shorthand

    a(f"# gh-iga Access Report — `{result.org}`")
    a("")
    a(f"**Scanned:** {result.scanned_at.strftime('%Y-%m-%d %H:%M UTC')}  ")
    a(f"**Tool:** gh-iga v{__version__}")
    a("")

    # ------------------------------------------------------------------
    # Summary table
    # ------------------------------------------------------------------
    a("## Summary")
    a("")
    a("| Metric | Count |")
    a("|--------|------:|")
    a(f"| Org members | {len(result.members)} |")
    a(f"| Org owners | {len(result.owners)} |")
    a(f"| Outside collaborators | {len(result.outside_collaborators)} |")
    a(f"| Active repos | {len(result.active_repos)} |")
    a(f"| Archived repos | {len(result.repos) - len(result.active_repos)} |")
    a(f"| Teams | {len(result.teams)} |")
    a(f"| Installed apps (NHIs) | {len(result.installed_apps)} |")
    a(f"| Deploy keys (NHIs) | {len(result.deploy_keys)} |")
    a(f"| High findings | {len(result.high_findings)} |")
    a(f"| Medium findings | {len(result.medium_findings)} |")
    a(f"| Low findings | {len(result.low_findings)} |")
    a("")

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------
    a("## Risk Findings")
    a("")

    if not result.findings:
        a("✅ No governance issues found.")
        a("")
    else:
        for finding in result.findings:
            badge = _SEVERITY_BADGE[finding.severity]
            a(f"### {badge} — {finding.title}")
            a("")
            a(f"_{finding.detail}_")
            a("")
            if finding.affected:
                a(f"**Affected ({finding.affected_count}):**")
                a("")
                for item in finding.affected:
                    a(f"- `{item}`")
                a("")

    # ------------------------------------------------------------------
    # Members table
    # ------------------------------------------------------------------
    a("## Members")
    a("")
    a("| Login | Role | Teams | Direct Repos | Last Active |")
    a("|-------|------|------:|-------------:|-------------|")
    for m in sorted(result.members, key=lambda x: (x.role != "owner", x.login)):
        teams_str = str(len(m.teams)) if m.teams else "—"
        repos_str = str(len(m.direct_repo_access)) if m.direct_repo_access else "—"
        active_str = (
            m.last_active.strftime("%Y-%m-%d") if m.last_active else "unknown"
        ) if result.activity_checked else "—"
        a(f"| `{m.login}` | {m.role} | {teams_str} | {repos_str} | {active_str} |")
    a("")

    # ------------------------------------------------------------------
    # Outside collaborators
    # ------------------------------------------------------------------
    if result.outside_collaborators:
        a("## Outside Collaborators")
        a("")
        a("| Login | Repos | Highest Permission |")
        a("|-------|------:|-------------------|")
        for oc in sorted(result.outside_collaborators, key=lambda x: x.login):
            if oc.repo_access:
                from ..models import highest_permission
                highest = highest_permission([r.permission for r in oc.repo_access])
                a(f"| `{oc.login}` | {len(oc.repo_access)} | {highest} |")
            else:
                a(f"| `{oc.login}` | 0 | — |")
        a("")

    # ------------------------------------------------------------------
    # Teams
    # ------------------------------------------------------------------
    if result.teams:
        a("## Teams")
        a("")
        a("| Team | Members | Repos |")
        a("|------|--------:|------:|")
        for team in sorted(result.teams, key=lambda t: t.name.lower()):
            a(f"| {team.name} | {len(team.member_logins)} | {len(team.repo_access)} |")
        a("")

    # ------------------------------------------------------------------
    # Installed apps (non-human identities)
    # ------------------------------------------------------------------
    if result.installed_apps:
        a("## Installed Apps (Non-Human Identities)")
        a("")
        a("| App | Permissions | Repo Scope | Status |")
        a("|-----|-------------|-----------|--------|")
        for app in sorted(result.installed_apps, key=lambda x: x.app_slug.lower()):
            perms = ", ".join(
                f"{k}:{v}" for k, v in sorted(app.permissions.items())
            ) or "—"
            scope = "all repos" if app.has_org_wide_access else "selected"
            status = "suspended" if app.is_suspended else "active"
            a(f"| `{app.app_slug}` | {perms} | {scope} | {status} |")
        a("")

    # ------------------------------------------------------------------
    # Deploy keys (non-human credentials)
    # ------------------------------------------------------------------
    if result.deploy_keys:
        a("## Deploy Keys (Non-Human Identities)")
        a("")
        a("| Repo | Key | Access | Last Used | Added By |")
        a("|------|-----|--------|-----------|----------|")
        for k in sorted(result.deploy_keys, key=lambda x: (x.repo_name.lower(), x.title.lower())):
            access = "read-write" if k.is_read_write else "read-only"
            last_used = k.last_used.strftime("%Y-%m-%d") if k.last_used else "never"
            a(f"| `{k.repo_name}` | {k.title or '—'} | {access} | {last_used} | {k.added_by or '—'} |")
        a("")

    # ------------------------------------------------------------------
    # Footer
    # ------------------------------------------------------------------
    a("---")
    a("")
    a(
        "_Generated by [gh-iga](https://github.com/abhishek20c/gh-iga) — "
        "the open-source identity governance scanner for GitHub._"
    )
    a("")

    path.write_text("\n".join(lines), encoding="utf-8")
