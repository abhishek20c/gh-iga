"""Governance rules — turns a ScanResult into a list of Findings."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Set

from .models import Finding, ScanResult, Severity, has_write_or_above


def generate_user_findings(result: ScanResult) -> List[Finding]:
    """Governance rules for a personal account scan (no org)."""
    findings: List[Finding] = []

    # Anyone with admin on your repos (other than you)
    admin_collabs = [
        (oc.login, [r.repo_name for r in oc.repo_access if r.permission == "admin"])
        for oc in result.outside_collaborators
        if any(r.permission == "admin" for r in oc.repo_access)
    ]
    if admin_collabs:
        findings.append(Finding(
            severity=Severity.HIGH,
            category="external_admins",
            title=f"{len(admin_collabs)} collaborator(s) have admin access to your repos",
            detail=(
                "These users have full admin rights on your repositories — they can delete "
                "the repo, change settings, and manage other collaborators. "
                "Verify each is intentional."
            ),
            affected=[f"{login} ({', '.join(repos)})" for login, repos in admin_collabs],
        ))

    # Anyone with write access
    write_collabs = [
        (oc.login, [r.repo_name for r in oc.repo_access if has_write_or_above(r.permission)])
        for oc in result.outside_collaborators
        if any(has_write_or_above(r.permission) for r in oc.repo_access)
        if not any(r.permission == "admin" for r in oc.repo_access)  # already flagged above
    ]
    if write_collabs:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="external_writers",
            title=f"{len(write_collabs)} collaborator(s) have write access to your repos",
            detail="These users can push code to your repositories. Confirm they are still active contributors.",
            affected=[f"{login} ({', '.join(repos)})" for login, repos in write_collabs],
        ))

    # Public repos (informational)
    public_repos = [r.name for r in result.repos if not r.is_private and not r.is_archived]
    if public_repos:
        findings.append(Finding(
            severity=Severity.LOW,
            category="public_repos",
            title=f"{len(public_repos)} repo(s) are public",
            detail="Public repos are visible to everyone. Ensure no secrets or sensitive data are committed.",
            affected=public_repos,
        ))

    return findings


def generate_findings(
    result: ScanResult,
    *,
    inactive_days: int = 90,
    admin_sprawl_threshold: int = 5,
    max_admins_per_repo: int = 3,
) -> List[Finding]:
    """Run all governance rules and return ordered findings (high → medium → low)."""
    findings: List[Finding] = []

    findings += _rule_admin_sprawl(result, admin_sprawl_threshold)
    findings += _rule_inactive_privileged(result, inactive_days)
    findings += _rule_privileged_outside_collaborators(result)
    findings += _rule_over_permissioned_repos(result, max_admins_per_repo)
    findings += _rule_orphaned_members(result)
    findings += _rule_direct_access_candidates(result)

    return findings


# ---------------------------------------------------------------------------
# Individual rules
# ---------------------------------------------------------------------------


def _rule_admin_sprawl(
    result: ScanResult, threshold: int
) -> List[Finding]:
    """Flag org members who have admin access to >= threshold active repos."""
    # Build: login → list of repo names where they are effective admin
    member_logins: Set[str] = {m.login for m in result.members}
    admin_repos: Dict[str, List[str]] = {}

    for repo in result.active_repos:
        for login in repo.unique_admins():
            if login in member_logins:
                admin_repos.setdefault(login, []).append(repo.name)

    sprawl = [
        (login, repos)
        for login, repos in admin_repos.items()
        if len(repos) >= threshold
    ]
    if not sprawl:
        return []

    sprawl.sort(key=lambda x: len(x[1]), reverse=True)

    return [
        Finding(
            severity=Severity.HIGH,
            category="admin_sprawl",
            title=f"{len(sprawl)} user(s) have admin access to {threshold}+ repos",
            detail=(
                f"These org members hold admin rights across {threshold} or more active repositories. "
                "Admin access should be scoped to repos where it is genuinely needed. "
                "Consider converting broad admin grants to maintain or write."
            ),
            affected=[f"{login} ({len(repos)} repos)" for login, repos in sprawl],
        )
    ]


def _rule_inactive_privileged(
    result: ScanResult, inactive_days: int
) -> List[Finding]:
    """Flag members inactive for >= inactive_days who still hold write/admin access."""
    if not result.activity_checked:
        return []

    cutoff = datetime.now(timezone.utc)
    flagged = []

    # Build per-member effective permissions across all repos
    member_logins: Set[str] = {m.login for m in result.members}
    member_privileged_repos: Dict[str, List[str]] = {}

    for repo in result.active_repos:
        for collab in repo.collaborators:
            if collab.login in member_logins and has_write_or_above(collab.permission):
                member_privileged_repos.setdefault(collab.login, []).append(repo.name)

    member_map = {m.login: m for m in result.members}

    for login, priv_repos in member_privileged_repos.items():
        member = member_map[login]
        if member.last_active is None:
            continue  # no activity data — skip rather than false-positive
        days_inactive = (cutoff - member.last_active).days
        if days_inactive >= inactive_days:
            flagged.append((login, days_inactive, list(set(priv_repos))))

    if not flagged:
        return []

    flagged.sort(key=lambda x: x[1], reverse=True)  # most inactive first

    return [
        Finding(
            severity=Severity.HIGH,
            category="inactive_privileged",
            title=(
                f"{len(flagged)} user(s) inactive {inactive_days}+ days "
                "still hold write or admin access"
            ),
            detail=(
                f"These users have not had any recorded activity in the org for over {inactive_days} days "
                "but retain write or admin rights on one or more repositories. "
                "They may be offboarded, on extended leave, or simply no longer contributing. "
                "Access should be reviewed and revoked where no longer needed."
            ),
            affected=[
                f"{login} (inactive {days}d, {len(repos)} repo(s))"
                for login, days, repos in flagged
            ],
        )
    ]


def _rule_privileged_outside_collaborators(result: ScanResult) -> List[Finding]:
    """Flag outside collaborators with write or admin on any repo."""
    privileged = []
    for oc in result.outside_collaborators:
        for ra in oc.repo_access:
            if has_write_or_above(ra.permission):
                privileged.append((oc.login, ra.repo_name, ra.permission))

    if not privileged:
        return []

    unique_users = len({x[0] for x in privileged})

    return [
        Finding(
            severity=Severity.HIGH,
            category="privileged_outside_collaborators",
            title=f"{unique_users} outside collaborator(s) have write or admin access",
            detail=(
                "Outside collaborators are not org members and bypass org-level policies "
                "(SSO enforcement, 2FA requirements, audit log attribution). "
                "Write or admin access for external users should be explicitly reviewed "
                "and preferably scoped to read-only where possible."
            ),
            affected=[
                f"{login} ({permission} on {repo})"
                for login, repo, permission in privileged
            ],
        )
    ]


def _rule_over_permissioned_repos(
    result: ScanResult, max_admins: int
) -> List[Finding]:
    """Flag active repos that have more than max_admins unique admins."""
    flagged = []
    for repo in result.active_repos:
        admin_logins = repo.unique_admins()
        if len(admin_logins) > max_admins:
            flagged.append((repo.name, admin_logins))

    if not flagged:
        return []

    flagged.sort(key=lambda x: len(x[1]), reverse=True)

    return [
        Finding(
            severity=Severity.MEDIUM,
            category="over_permissioned_repos",
            title=f"{len(flagged)} repo(s) have more than {max_admins} admins",
            detail=(
                f"Repositories with more than {max_admins} admins are harder to audit and "
                "increase the blast radius of a compromised account. "
                "Consider reducing admin grants to a single owning team."
            ),
            affected=[
                f"{repo} ({len(admins)} admins)" for repo, admins in flagged
            ],
        )
    ]


def _rule_orphaned_members(result: ScanResult) -> List[Finding]:
    """Flag non-owner org members with no team membership and no direct repo access."""
    members_with_teams: Set[str] = {m.login for m in result.members if m.teams}
    members_with_repos: Set[str] = {
        collab.login
        for repo in result.repos
        for collab in repo.collaborators
    }

    orphaned = [
        m
        for m in result.members
        if m.role != "owner"
        and m.login not in members_with_teams
        and m.login not in members_with_repos
    ]

    if not orphaned:
        return []

    return [
        Finding(
            severity=Severity.MEDIUM,
            category="orphaned_members",
            title=f"{len(orphaned)} org member(s) have no team and no repo access",
            detail=(
                "These users are org members but belong to no team and have no direct "
                "repository access. They can read any public-within-org repo by default. "
                "This is often a sign of incomplete onboarding, pending offboarding, "
                "or a stale invitation that was accepted."
            ),
            affected=[m.login for m in orphaned],
        )
    ]


def _rule_direct_access_candidates(result: ScanResult) -> List[Finding]:
    """Flag members who have direct repo access that overlaps with their team access.

    These users could have their direct grants removed and rely solely on team
    membership — reducing the number of individual permissions to audit.
    """
    # Build: login → set of repos covered by their teams
    team_coverage: Dict[str, Set[str]] = {}
    for team in result.teams:
        for login in team.member_logins:
            for ra in team.repo_access:
                team_coverage.setdefault(login, set()).add(ra.repo_name)

    flagged = []
    for member in result.members:
        direct = {ra.repo_name for ra in member.direct_repo_access}
        covered_by_team = team_coverage.get(member.login, set())
        redundant = direct & covered_by_team
        if redundant:
            flagged.append((member.login, sorted(redundant)))

    if not flagged:
        return []

    return [
        Finding(
            severity=Severity.LOW,
            category="direct_access_candidates",
            title=(
                f"{len(flagged)} user(s) have direct repo access "
                "already covered by their team membership"
            ),
            detail=(
                "These users have both individual direct-access grants and team-based "
                "access to the same repositories. The direct grants are redundant and "
                "can be removed. Team-based access is easier to audit and revoke at scale."
            ),
            affected=[
                f"{login} ({len(repos)} redundant repo(s))"
                for login, repos in flagged
            ],
        )
    ]
