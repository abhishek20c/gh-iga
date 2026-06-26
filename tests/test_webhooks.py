"""Tests for webhook (third-party trust) inventory and rules."""

from __future__ import annotations

import responses

from gh_iga.models import Member, ScanResult, Webhook
from gh_iga.rules import generate_webhook_findings
from gh_iga.scanner import GitHubClient, _parse_webhook


def _result(*hooks: Webhook) -> ScanResult:
    return ScanResult(
        org="acme",
        scanned_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        members=[Member("alice", None, "owner")],
        outside_collaborators=[],
        repos=[],
        teams=[],
        webhooks=list(hooks),
    )


def _categories(result: ScanResult):
    return {f.category for f in generate_webhook_findings(result)}


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_parse_webhook_with_secret_and_https():
    raw = {
        "id": 1, "active": True, "events": ["push"],
        "config": {"url": "https://ci.example.com/hook", "secret": "********", "insecure_ssl": "0"},
    }
    w = _parse_webhook(raw, "repo", "web")
    assert w.url == "https://ci.example.com/hook"
    assert w.has_secret is True
    assert w.insecure_ssl is False
    assert w.is_http is False
    assert w.is_insecure_transport is False


def test_parse_webhook_no_secret_http():
    raw = {"id": 2, "active": True, "config": {"url": "http://legacy.example.com/hook"}}
    w = _parse_webhook(raw, "org")
    assert w.has_secret is False
    assert w.is_http is True
    assert w.is_insecure_transport is True


def test_parse_webhook_insecure_ssl():
    raw = {"id": 3, "active": True,
           "config": {"url": "https://x.example.com", "secret": "********", "insecure_ssl": "1"}}
    w = _parse_webhook(raw, "org")
    assert w.is_insecure_transport is True  # SSL verification disabled


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def test_no_secret_flagged():
    r = _result(Webhook(1, "repo", "https://x/h", active=True, has_secret=False,
                        insecure_ssl=False, repo_name="web"))
    assert "webhooks_no_secret" in _categories(r)


def test_insecure_transport_flagged():
    r = _result(Webhook(1, "org", "http://x/h", active=True, has_secret=True, insecure_ssl=False))
    assert "webhooks_insecure_transport" in _categories(r)


def test_secure_webhook_not_flagged():
    r = _result(Webhook(1, "org", "https://x/h", active=True, has_secret=True, insecure_ssl=False))
    assert generate_webhook_findings(r) == []


def test_inactive_webhook_not_flagged():
    # An inactive webhook isn't a live risk
    r = _result(Webhook(1, "org", "http://x/h", active=False, has_secret=False, insecure_ssl=False))
    assert generate_webhook_findings(r) == []


def test_no_webhooks_no_findings():
    assert generate_webhook_findings(_result()) == []


# ---------------------------------------------------------------------------
# Client (mocked HTTP)
# ---------------------------------------------------------------------------


@responses.activate
def test_get_repo_webhooks():
    responses.add(
        responses.GET,
        "https://api.github.com/repos/acme/web/hooks",
        json=[{"id": 1, "active": True, "config": {"url": "https://x/h"}}],
        status=200,
    )
    client = GitHubClient("token")
    hooks = client.get_repo_webhooks("acme", "web")
    assert hooks[0]["id"] == 1


@responses.activate
def test_get_org_webhooks():
    responses.add(
        responses.GET,
        "https://api.github.com/orgs/acme/hooks",
        json=[{"id": 9, "active": True, "config": {"url": "https://o/h"}}],
        status=200,
    )
    client = GitHubClient("token")
    assert client.get_org_webhooks("acme")[0]["id"] == 9
