"""Tests for deploy-key (non-human credential) inventory and rules."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import responses

from gh_iga.models import DeployKey, Member, ScanResult
from gh_iga.rules import generate_deploy_key_findings
from gh_iga.scanner import GitHubClient, _parse_deploy_key

_NOW = datetime.now(timezone.utc)


def _result(*keys: DeployKey) -> ScanResult:
    return ScanResult(
        org="acme",
        scanned_at=_NOW,
        members=[Member("alice", None, "owner")],
        outside_collaborators=[],
        repos=[],
        teams=[],
        deploy_keys=list(keys),
    )


def _categories(result: ScanResult):
    return {f.category for f in generate_deploy_key_findings(result)}


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_parse_deploy_key_full():
    raw = {
        "id": 5,
        "title": "ci-deploy",
        "read_only": False,
        "created_at": "2023-01-01T00:00:00Z",
        "last_used": "2024-06-01T00:00:00Z",
        "added_by": "alice",
    }
    k = _parse_deploy_key(raw, "web-app")
    assert k.key_id == 5
    assert k.repo_name == "web-app"
    assert k.is_read_write is True
    assert k.added_by == "alice"
    assert k.created_at == datetime(2023, 1, 1, tzinfo=timezone.utc)


def test_parse_deploy_key_defaults_read_only_true():
    # GitHub omits read_only sometimes; default to the safe (read-only) assumption
    k = _parse_deploy_key({"id": 1, "title": "k"}, "repo")
    assert k.read_only is True
    assert k.is_read_write is False
    assert k.last_used is None


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def test_read_write_key_flagged():
    r = _result(DeployKey(1, "rw", "web", read_only=False, created_at=_NOW, last_used=_NOW))
    cats = _categories(r)
    assert "deploy_keys_read_write" in cats
    assert "deploy_keys_stale" not in cats  # fresh


def test_read_only_fresh_key_not_flagged():
    r = _result(DeployKey(1, "ro", "web", read_only=True, created_at=_NOW, last_used=_NOW))
    assert generate_deploy_key_findings(r) == []


def test_stale_never_used_old_key_flagged():
    r = _result(
        DeployKey(
            1, "old", "api", read_only=True, created_at=_NOW - timedelta(days=400), last_used=None
        )
    )
    cats = _categories(r)
    assert "deploy_keys_stale" in cats


def test_stale_used_long_ago_flagged():
    r = _result(
        DeployKey(
            1,
            "k",
            "api",
            read_only=True,
            created_at=_NOW - timedelta(days=500),
            last_used=_NOW - timedelta(days=200),
        )
    )
    assert "deploy_keys_stale" in _categories(r)


def test_new_unused_key_not_stale():
    # Created recently, never used → must NOT be flagged stale (avoids false positives)
    r = _result(
        DeployKey(
            1, "new", "x", read_only=True, created_at=_NOW - timedelta(days=5), last_used=None
        )
    )
    assert "deploy_keys_stale" not in _categories(r)


def test_no_keys_no_findings():
    assert generate_deploy_key_findings(_result()) == []


# ---------------------------------------------------------------------------
# Client (mocked HTTP)
# ---------------------------------------------------------------------------


@responses.activate
def test_get_repo_deploy_keys():
    responses.add(
        responses.GET,
        "https://api.github.com/repos/acme/web/keys",
        json=[
            {"id": 1, "title": "ci", "read_only": False},
            {"id": 2, "title": "backup", "read_only": True},
        ],
        status=200,
    )
    client = GitHubClient("token")
    keys = client.get_repo_deploy_keys("acme", "web")
    assert [k["title"] for k in keys] == ["ci", "backup"]
