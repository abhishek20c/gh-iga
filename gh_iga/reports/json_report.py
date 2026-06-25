"""JSON report writer — machine-readable output for pipelines and SIEMs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from .. import __version__
from ..models import ScanResult


def _member_to_dict(m: Any) -> Dict:
    return {
        "login": m.login,
        "name": m.name,
        "role": m.role,
        "last_active": m.last_active.isoformat() if m.last_active else None,
        "days_since_active": m.days_since_active,
        "teams": m.teams,
        "direct_repo_count": len(m.direct_repo_access),
        "direct_repos": [
            {"repo": r.repo_name, "permission": r.permission}
            for r in m.direct_repo_access
        ],
    }


def _outside_collab_to_dict(oc: Any) -> Dict:
    return {
        "login": oc.login,
        "repo_count": len(oc.repo_access),
        "repos": [
            {"repo": r.repo_name, "permission": r.permission}
            for r in oc.repo_access
        ],
    }


def _repo_to_dict(r: Any) -> Dict:
    # Deduplicate collaborators: keep highest permission per login
    seen: Dict[str, Dict] = {}
    for c in r.collaborators:
        from ..models import PERMISSION_RANK
        rank = PERMISSION_RANK.get(c.permission, 0)
        if c.login not in seen or rank > PERMISSION_RANK.get(seen[c.login]["permission"], 0):
            seen[c.login] = {"login": c.login, "permission": c.permission, "source": c.source}

    return {
        "name": r.name,
        "full_name": r.full_name,
        "private": r.is_private,
        "archived": r.is_archived,
        "description": r.description,
        "admin_count": len(r.unique_admins()),
        "collaborators": list(seen.values()),
    }


def _team_to_dict(t: Any) -> Dict:
    return {
        "name": t.name,
        "slug": t.slug,
        "description": t.description,
        "member_count": len(t.member_logins),
        "members": t.member_logins,
        "repo_count": len(t.repo_access),
        "repos": [
            {"repo": r.repo_name, "permission": r.permission}
            for r in t.repo_access
        ],
    }


def _app_to_dict(a: Any) -> Dict:
    return {
        "app_slug": a.app_slug,
        "app_id": a.app_id,
        "installation_id": a.installation_id,
        "permissions": a.permissions,
        "repository_selection": a.repository_selection,
        "org_wide_access": a.has_org_wide_access,
        "privileged_permissions": a.privileged_permissions(),
        "suspended": a.is_suspended,
        "events": a.events,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
    }


def _pat_to_dict(p: Any) -> Dict:
    return {
        "token_id": p.token_id,
        "token_name": p.token_name,
        "owner": p.owner,
        "repository_selection": p.repository_selection,
        "org_wide_access": p.has_org_wide_access,
        "no_expiry": p.has_no_expiry,
        "expired": p.token_expired,
        "privileged_permissions": p.privileged_permissions(),
        "access_granted_at": p.access_granted_at.isoformat() if p.access_granted_at else None,
        "expires_at": p.token_expires_at.isoformat() if p.token_expires_at else None,
        "last_used_at": p.token_last_used_at.isoformat() if p.token_last_used_at else None,
    }


def _finding_to_dict(f: Any) -> Dict:
    return {
        "severity": f.severity,
        "category": f.category,
        "title": f.title,
        "detail": f.detail,
        "affected_count": f.affected_count,
        "affected": f.affected,
    }


def write_json_report(result: ScanResult, path: Path) -> None:
    payload = {
        "meta": {
            "tool": "gh-iga",
            "version": __version__,
            "org": result.org,
            "scanned_at": result.scanned_at.isoformat(),
            "activity_checked": result.activity_checked,
        },
        "summary": {
            "member_count": len(result.members),
            "owner_count": len(result.owners),
            "outside_collaborator_count": len(result.outside_collaborators),
            "repo_count": len(result.repos),
            "active_repo_count": len(result.active_repos),
            "team_count": len(result.teams),
            "installed_app_count": len(result.installed_apps),
            "org_pat_count": len(result.org_pats),
            "finding_count": len(result.findings),
            "high_findings": len(result.high_findings),
            "medium_findings": len(result.medium_findings),
            "low_findings": len(result.low_findings),
        },
        "findings": [_finding_to_dict(f) for f in result.findings],
        "members": [_member_to_dict(m) for m in result.members],
        "outside_collaborators": [_outside_collab_to_dict(oc) for oc in result.outside_collaborators],
        "repos": [_repo_to_dict(r) for r in result.repos],
        "teams": [_team_to_dict(t) for t in result.teams],
        "installed_apps": [_app_to_dict(a) for a in result.installed_apps],
        "org_pats": [_pat_to_dict(p) for p in result.org_pats],
    }

    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
