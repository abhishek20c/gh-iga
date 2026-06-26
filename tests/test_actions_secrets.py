"""Tests for GitHub Actions secret (long-lived credential) inventory and rules."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import responses

from gh_iga.models import ActionsSecret, Member, ScanResult
from gh_iga.rules import generate_secret_findings
from gh_iga.scanner import GitHubClient, _parse_actions_secret

_NOW = datetime.now(timezone.utc)


def _result(*secrets: ActionsSecret) -> ScanResult:
    return ScanResult(
        org="acme",
        scanned_at=_NOW,
        members=[Member("alice", None, "owner")],
        outside_collaborators=[],
        repos=[],
        teams=[],
        actions_secrets=list(secrets),
    )


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_parse_repo_secret():
    raw = {"name": "GH_TOKEN", "created_at": "2022-01-01T00:00:00Z",
           "updated_at": "2022-06-01T00:00:00Z"}
    s = _parse_actions_secret(raw, "repo", "web")
    assert s.name == "GH_TOKEN"
    assert s.level == "repo"
    assert s.repo_name == "web"
    assert s.updated_at == datetime(2022, 6, 1, tzinfo=timezone.utc)


def test_parse_org_secret_visibility():
    raw = {"name": "NPM_TOKEN", "visibility": "all",
           "created_at": "2023-01-01T00:00:00Z", "updated_at": "2023-01-01T00:00:00Z"}
    s = _parse_actions_secret(raw, "org")
    assert s.level == "org"
    assert s.repo_name is None
    assert s.visibility == "all"


def test_days_since_rotated_uses_updated_then_created():
    s = ActionsSecret("X", "org", updated_at=_NOW - timedelta(days=10))
    assert s.days_since_rotated(_NOW) == 10
    s2 = ActionsSecret("Y", "org", created_at=_NOW - timedelta(days=30), updated_at=None)
    assert s2.days_since_rotated(_NOW) == 30
    s3 = ActionsSecret("Z", "org")
    assert s3.days_since_rotated(_NOW) is None


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def test_stale_secret_flagged():
    r = _result(ActionsSecret("OLD", "repo", repo_name="api",
                              updated_at=_NOW - timedelta(days=400)))
    findings = generate_secret_findings(r)
    assert len(findings) == 1
    assert findings[0].category == "secrets_not_rotated"
    assert findings[0].severity == "medium"
    assert "api/OLD" in findings[0].affected[0]


def test_fresh_secret_not_flagged():
    r = _result(ActionsSecret("NEW", "org", updated_at=_NOW - timedelta(days=30)))
    assert generate_secret_findings(r) == []


def test_secret_unknown_timestamp_not_flagged():
    r = _result(ActionsSecret("NOINFO", "org"))
    assert generate_secret_findings(r) == []


def test_no_secrets_no_findings():
    assert generate_secret_findings(_result()) == []


# ---------------------------------------------------------------------------
# Client (mocked HTTP)
# ---------------------------------------------------------------------------


@responses.activate
def test_get_repo_actions_secrets_unwraps():
    responses.add(
        responses.GET,
        "https://api.github.com/repos/acme/web/actions/secrets",
        json={"total_count": 2, "secrets": [
            {"name": "A", "created_at": "2022-01-01T00:00:00Z", "updated_at": "2022-01-01T00:00:00Z"},
            {"name": "B", "created_at": "2023-01-01T00:00:00Z", "updated_at": "2023-01-01T00:00:00Z"},
        ]},
        status=200,
    )
    client = GitHubClient("token")
    secrets = client.get_repo_actions_secrets("acme", "web")
    assert [s["name"] for s in secrets] == ["A", "B"]


@responses.activate
def test_get_org_actions_secrets_unwraps():
    responses.add(
        responses.GET,
        "https://api.github.com/orgs/acme/actions/secrets",
        json={"total_count": 1, "secrets": [{"name": "ORG_TOKEN", "visibility": "all"}]},
        status=200,
    )
    client = GitHubClient("token")
    secrets = client.get_org_actions_secrets("acme")
    assert secrets[0]["name"] == "ORG_TOKEN"
