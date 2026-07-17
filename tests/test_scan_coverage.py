"""Regression tests for scan completeness reporting."""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone

import pytest
import requests
from rich.console import Console

from gh_iga.models import Member, ScanCoverage, ScanResult
from gh_iga.reports.html import write_html_report
from gh_iga.reports.json_report import write_json_report
from gh_iga.reports.markdown import write_markdown_report
from gh_iga.reports.terminal import print_summary
from gh_iga.scanner import (
    GitHubClient,
    _record_optional_http_error,
    scan_user,
)


def _http_error(status: int, *, remaining: str | None = None) -> requests.HTTPError:
    response = requests.Response()
    response.status_code = status
    if remaining is not None:
        response.headers["X-RateLimit-Remaining"] = remaining
    return requests.HTTPError(response=response)


def _partial_result() -> ScanResult:
    deploy_keys = ScanCoverage(area="deploy_keys", label="Deploy keys")
    deploy_keys.record_success()
    deploy_keys.record_skip("repo:private", "insufficient_permission", 403)
    return ScanResult(
        org="acme",
        scanned_at=datetime.now(timezone.utc),
        members=[Member("alice", None, "owner")],
        outside_collaborators=[],
        repos=[],
        teams=[],
        coverage=[deploy_keys],
    )


def test_coverage_distinguishes_complete_partial_skipped_and_not_applicable():
    complete = ScanCoverage("apps", "Apps")
    complete.record_success()

    partial = ScanCoverage("keys", "Keys")
    partial.record_success()
    partial.record_skip("repo:private", "insufficient_permission", 403)

    skipped = ScanCoverage("hooks", "Hooks")
    skipped.record_skip("org", "insufficient_permission", 403)

    not_applicable = ScanCoverage("apps", "Apps", applicable=False)

    assert complete.status == "complete"
    assert partial.status == "partial"
    assert skipped.status == "skipped"
    assert not_applicable.status == "not_applicable"


def test_expected_permission_error_is_recorded():
    coverage = ScanCoverage("keys", "Deploy keys")

    _record_optional_http_error(coverage, "repo:private", _http_error(403))

    assert coverage.status == "skipped"
    assert coverage.attempted == 1
    assert coverage.succeeded == 0
    assert coverage.issues[0].reason == "insufficient_permission"
    assert coverage.issues[0].status_code == 403


@pytest.mark.parametrize(
    "error",
    [
        _http_error(401),
        _http_error(403, remaining="0"),
        _http_error(429),
        _http_error(500),
    ],
)
def test_unexpected_http_errors_are_not_silently_downgraded(error):
    coverage = ScanCoverage("keys", "Deploy keys")

    with pytest.raises(requests.HTTPError):
        _record_optional_http_error(coverage, "repo:private", error)

    assert coverage.attempted == 0


def test_personal_scan_records_per_repository_coverage(monkeypatch):
    monkeypatch.setattr(
        GitHubClient,
        "get_authenticated_user",
        lambda self: {"login": "alice", "name": "Alice"},
    )
    monkeypatch.setattr(
        GitHubClient,
        "get_user_repos",
        lambda self: [
            {
                "name": "public",
                "full_name": "alice/public",
                "private": False,
                "archived": False,
            },
            {
                "name": "private",
                "full_name": "alice/private",
                "private": True,
                "archived": False,
            },
        ],
    )
    monkeypatch.setattr(GitHubClient, "get_repo_collaborators", lambda self, owner, repo: [])

    def deploy_keys(self, owner, repo):
        if repo == "private":
            raise _http_error(403)
        return []

    monkeypatch.setattr(GitHubClient, "get_repo_deploy_keys", deploy_keys)
    monkeypatch.setattr(GitHubClient, "get_repo_actions_secrets", lambda self, owner, repo: [])
    monkeypatch.setattr(GitHubClient, "get_repo_webhooks", lambda self, owner, repo: [])
    monkeypatch.setattr(
        GitHubClient,
        "get_repo_workflow_permissions",
        lambda self, owner, repo: {
            "default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": False,
        },
    )

    result = scan_user(
        "token", console=Console(file=io.StringIO(), width=100, legacy_windows=False)
    )
    coverage = {item.area: item for item in result.coverage}

    assert result.scan_status == "partial"
    assert coverage["installed_apps"].status == "not_applicable"
    assert coverage["deploy_keys"].status == "partial"
    assert coverage["deploy_keys"].attempted == 2
    assert coverage["deploy_keys"].succeeded == 1
    assert coverage["deploy_keys"].issues[0].scope == "repo:private"
    assert coverage["actions_secrets"].status == "complete"


def test_partial_coverage_is_visible_in_every_report(tmp_path):
    result = _partial_result()
    json_path = tmp_path / "report.json"
    markdown_path = tmp_path / "report.md"
    html_path = tmp_path / "report.html"

    write_json_report(result, json_path)
    write_markdown_report(result, markdown_path)
    write_html_report(result, html_path)

    stream = io.StringIO()
    print_summary(
        result,
        console=Console(file=stream, width=100, legacy_windows=False),
    )

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    markdown = markdown_path.read_text(encoding="utf-8")
    html = html_path.read_text(encoding="utf-8")
    terminal = stream.getvalue()

    assert payload["meta"]["scan_status"] == "partial"
    assert payload["coverage"]["deploy_keys"]["status"] == "partial"
    assert payload["coverage"]["deploy_keys"]["issues"][0]["scope"] == "repo:private"
    assert "Partial scan" in markdown
    assert "repo:private" in markdown
    assert "Partial scan" in html
    assert "repo:private" in html
    assert "Partial scan" in terminal
    assert "repo:private" in terminal
