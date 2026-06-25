"""Tests for fine-grained PAT (non-human credential) inventory and rules."""

from __future__ import annotations

from datetime import datetime, timezone

import responses

from gh_iga.models import FineGrainedPAT, Member, ScanResult
from gh_iga.rules import generate_pat_findings
from gh_iga.scanner import GitHubClient, _parse_pat


def _result(*pats: FineGrainedPAT) -> ScanResult:
    return ScanResult(
        org="acme",
        scanned_at=datetime.now(timezone.utc),
        members=[Member("alice", None, "owner")],
        outside_collaborators=[],
        repos=[],
        teams=[],
        org_pats=list(pats),
    )


def _categories(result: ScanResult):
    return {f.category for f in generate_pat_findings(result)}


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_parse_pat_full():
    raw = {
        "token_id": 5,
        "token_name": "ci-token",
        "owner": {"login": "octocat"},
        "repository_selection": "all",
        "permissions": {"repository": {"contents": "write", "metadata": "read"},
                        "organization": {"members": "read"}},
        "access_granted_at": "2025-01-01T00:00:00Z",
        "token_expires_at": None,
        "token_last_used_at": "2025-06-01T00:00:00Z",
        "token_expired": False,
    }
    pat = _parse_pat(raw)
    assert pat.owner == "octocat"
    assert pat.token_name == "ci-token"
    assert pat.has_org_wide_access is True
    assert pat.has_no_expiry is True
    assert pat.privileged_permissions() == ["repository:contents"]


def test_parse_pat_handles_missing_fields():
    pat = _parse_pat({})
    assert pat.owner == ""
    assert pat.repository_selection == "none"
    assert pat.has_org_wide_access is False
    assert pat.has_no_expiry is True  # no expires_at → no expiry


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def test_no_expiry_flagged_high():
    r = _result(FineGrainedPAT(1, "tok", "alice", "subset", {}, token_expires_at=None))
    findings = generate_pat_findings(r)
    f = [x for x in findings if x.category == "pats_no_expiry"]
    assert len(f) == 1 and f[0].severity == "high"
    assert "alice (tok)" in f[0].affected


def test_pat_with_expiry_not_flagged_no_expiry():
    r = _result(FineGrainedPAT(1, "tok", "alice", "subset", {},
                               token_expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc)))
    assert "pats_no_expiry" not in _categories(r)


def test_org_wide_pat_flagged_medium():
    r = _result(FineGrainedPAT(1, "tok", "alice", "all", {},
                               token_expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc)))
    cats = _categories(r)
    assert "pats_org_wide_access" in cats


def test_expired_pat_excluded():
    """An already-expired PAT is not a live risk and should not be flagged."""
    r = _result(FineGrainedPAT(1, "tok", "alice", "all", {},
                               token_expires_at=None, token_expired=True))
    assert _categories(r) == set()


def test_no_pats_no_findings():
    assert generate_pat_findings(_result()) == []


# ---------------------------------------------------------------------------
# Client (mocked HTTP)
# ---------------------------------------------------------------------------


@responses.activate
def test_get_org_pats():
    responses.add(
        responses.GET,
        "https://api.github.com/orgs/acme/personal-access-tokens",
        json=[
            {"token_id": 1, "token_name": "ci", "owner": {"login": "alice"},
             "repository_selection": "all", "permissions": {}},
        ],
        status=200,
    )
    client = GitHubClient("token")
    pats = client.get_org_pats("acme")
    assert pats[0]["owner"]["login"] == "alice"
