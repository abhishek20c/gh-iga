"""Tests for Actions workflow GITHUB_TOKEN permission findings (NHI5)."""

from __future__ import annotations

from datetime import datetime, timezone

import responses

from gh_iga.models import Member, ScanResult, WorkflowPermissions
from gh_iga.reports.html import write_html_report
from gh_iga.reports.markdown import write_markdown_report
from gh_iga.rules import generate_workflow_findings
from gh_iga.scanner import GitHubClient, _parse_workflow_permissions


def _result(*perms: WorkflowPermissions) -> ScanResult:
    return ScanResult(
        org="acme",
        scanned_at=datetime.now(timezone.utc),
        members=[Member("alice", None, "owner")],
        outside_collaborators=[],
        repos=[],
        teams=[],
        workflow_permissions=list(perms),
    )


def _categories(result: ScanResult):
    return {f.category for f in generate_workflow_findings(result)}


def _wf(level, default, repo=None, approve=False):
    return WorkflowPermissions(
        level=level,
        default_permissions=default,
        can_approve_pull_requests=approve,
        repo_name=repo,
    )


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_parse_workflow_permissions():
    raw = {"default_workflow_permissions": "write", "can_approve_pull_request_reviews": True}
    w = _parse_workflow_permissions(raw, "org")
    assert w.is_write_default is True
    assert w.can_approve_pull_requests is True
    assert w.level == "org"


def test_parse_defaults_to_read():
    w = _parse_workflow_permissions({}, "repo", "web")
    assert w.default_permissions == "read"
    assert w.is_write_default is False
    assert w.can_approve_pull_requests is False


# ---------------------------------------------------------------------------
# Rules — noise-aware write-default
# ---------------------------------------------------------------------------


def test_org_write_default_reported_once_not_per_repo():
    # Org default is write; repos inherit it → report org once, NOT every repo
    r = _result(
        _wf("org", "write"),
        _wf("repo", "write", repo="a"),
        _wf("repo", "write", repo="b"),
    )
    findings = [
        f for f in generate_workflow_findings(r) if f.category == "workflow_token_write_default"
    ]
    assert len(findings) == 1
    assert findings[0].affected == ["org default (all repos inherit read-write)"]


def test_org_read_flags_individual_write_repos():
    # Org default is read; only the repos that opt up to write are flagged
    r = _result(
        _wf("org", "read"),
        _wf("repo", "write", repo="risky"),
        _wf("repo", "read", repo="safe"),
    )
    findings = [
        f for f in generate_workflow_findings(r) if f.category == "workflow_token_write_default"
    ]
    assert len(findings) == 1
    assert findings[0].affected == ["risky"]


def test_all_read_no_finding():
    r = _result(_wf("org", "read"), _wf("repo", "read", repo="a"))
    assert "workflow_token_write_default" not in _categories(r)


def test_can_approve_prs_flagged():
    r = _result(_wf("org", "read", approve=True))
    assert "workflow_can_approve_prs" in _categories(r)


def test_no_data_no_findings():
    assert generate_workflow_findings(_result()) == []


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


def test_workflow_permissions_render_in_human_readable_reports(tmp_path):
    r = _result(
        _wf("org", "write", approve=True),
        _wf("repo", "read", repo="web"),
    )

    md_path = tmp_path / "report.md"
    html_path = tmp_path / "report.html"

    write_markdown_report(r, md_path)
    write_html_report(r, html_path)

    markdown = md_path.read_text(encoding="utf-8")
    html = html_path.read_text(encoding="utf-8")

    assert "GitHub Actions Workflow Permissions (GITHUB_TOKEN)" in markdown
    assert "| org | write | yes |" in markdown
    assert "| repo: web | read | no |" in markdown
    assert "GitHub Actions Workflow Permissions" in html
    assert "GITHUB_TOKEN" in html
    assert "repo: web" in html


# ---------------------------------------------------------------------------
# Client (mocked HTTP)
# ---------------------------------------------------------------------------


@responses.activate
def test_get_repo_workflow_permissions():
    responses.add(
        responses.GET,
        "https://api.github.com/repos/acme/web/actions/permissions/workflow",
        json={"default_workflow_permissions": "write", "can_approve_pull_request_reviews": False},
        status=200,
    )
    client = GitHubClient("token")
    data = client.get_repo_workflow_permissions("acme", "web")
    assert data["default_workflow_permissions"] == "write"


@responses.activate
def test_get_org_workflow_permissions():
    responses.add(
        responses.GET,
        "https://api.github.com/orgs/acme/actions/permissions/workflow",
        json={"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False},
        status=200,
    )
    client = GitHubClient("token")
    assert client.get_org_workflow_permissions("acme")["default_workflow_permissions"] == "read"
