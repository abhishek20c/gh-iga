"""Tests for GitHub App (non-human identity) inventory and rules."""

from __future__ import annotations

from datetime import datetime, timezone

import responses

from gh_iga.models import InstalledApp, Member, ScanResult
from gh_iga.rules import generate_app_findings
from gh_iga.scanner import GitHubClient, _parse_installation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _result(*apps: InstalledApp) -> ScanResult:
    return ScanResult(
        org="acme",
        scanned_at=datetime.now(timezone.utc),
        members=[Member("alice", None, "owner")],
        outside_collaborators=[],
        repos=[],
        teams=[],
        installed_apps=list(apps),
    )


def _categories(result: ScanResult):
    return {f.category for f in generate_app_findings(result)}


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_parse_installation_full():
    raw = {
        "id": 42,
        "app_id": 7,
        "app_slug": "dependabot",
        "permissions": {"contents": "write", "metadata": "read"},
        "repository_selection": "all",
        "events": ["push"],
        "created_at": "2024-01-15T10:00:00Z",
        "updated_at": "2025-02-01T10:00:00Z",
        "suspended_at": None,
    }
    app = _parse_installation(raw)
    assert app.app_slug == "dependabot"
    assert app.installation_id == 42
    assert app.has_org_wide_access is True
    assert app.is_suspended is False
    assert app.privileged_permissions() == ["contents"]
    assert app.created_at == datetime(2024, 1, 15, 10, 0, tzinfo=timezone.utc)


def test_parse_installation_handles_missing_fields():
    app = _parse_installation({})
    assert app.app_slug == ""
    assert app.permissions == {}
    assert app.repository_selection == "selected"
    assert app.has_org_wide_access is False
    assert app.is_suspended is False
    assert app.created_at is None


def test_parse_installation_suspended():
    app = _parse_installation(
        {"app_slug": "old", "suspended_at": "2025-01-01T00:00:00Z", "permissions": {}}
    )
    assert app.is_suspended is True


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def test_admin_app_flagged_high():
    r = _result(InstalledApp("codecov", 1, 1, {"administration": "admin"}, "selected"))
    findings = generate_app_findings(r)
    admin = [f for f in findings if f.category == "apps_admin_permissions"]
    assert len(admin) == 1
    assert admin[0].severity == "high"
    assert "codecov (administration)" in admin[0].affected


def test_write_app_flagged_medium_not_admin():
    r = _result(InstalledApp("bot", 1, 1, {"contents": "write", "metadata": "read"}, "selected"))
    cats = _categories(r)
    assert "apps_write_permissions" in cats
    assert "apps_admin_permissions" not in cats


def test_readonly_app_not_flagged_for_permissions():
    r = _result(InstalledApp("readonly", 1, 1, {"metadata": "read"}, "selected"))
    cats = _categories(r)
    assert "apps_admin_permissions" not in cats
    assert "apps_write_permissions" not in cats


def test_org_wide_access_flagged():
    r = _result(InstalledApp("wide", 1, 1, {"metadata": "read"}, "all"))
    cats = _categories(r)
    assert "apps_org_wide_access" in cats


def test_suspended_app_excluded_from_active_rules():
    """A suspended app should only surface as a suspended finding, not as a live risk."""
    r = _result(
        InstalledApp(
            "old", 1, 1, {"administration": "admin"}, "all",
            suspended_at=datetime.now(timezone.utc),
        )
    )
    cats = _categories(r)
    assert cats == {"apps_suspended_installed"}


def test_no_apps_no_findings():
    assert generate_app_findings(_result()) == []


# ---------------------------------------------------------------------------
# Client (mocked HTTP)
# ---------------------------------------------------------------------------


@responses.activate
def test_get_org_app_installations_unwraps_object():
    responses.add(
        responses.GET,
        "https://api.github.com/orgs/acme/installations",
        json={
            "total_count": 2,
            "installations": [
                {"id": 1, "app_id": 10, "app_slug": "dependabot",
                 "permissions": {"contents": "write"}, "repository_selection": "all"},
                {"id": 2, "app_id": 20, "app_slug": "codecov",
                 "permissions": {"metadata": "read"}, "repository_selection": "selected"},
            ],
        },
        status=200,
    )
    client = GitHubClient("token")
    apps = client.get_org_app_installations("acme")
    assert [a["app_slug"] for a in apps] == ["dependabot", "codecov"]
