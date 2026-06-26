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

    findings += generate_app_findings(result)
    findings += generate_deploy_key_findings(result)
    findings += generate_secret_findings(result)
    findings += generate_webhook_findings(result)

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
    findings += generate_app_findings(result)
    findings += generate_deploy_key_findings(result, inactive_days)
    findings += generate_secret_findings(result)
    findings += generate_webhook_findings(result)

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


# ---------------------------------------------------------------------------
# Non-human identity rules — installed GitHub Apps
# ---------------------------------------------------------------------------


def generate_app_findings(result: ScanResult) -> List[Finding]:
    """Governance rules for installed GitHub Apps (non-human identities)."""
    findings: List[Finding] = []
    findings += _rule_overprivileged_apps(result)
    findings += _rule_org_wide_apps(result)
    findings += _rule_suspended_apps(result)
    return findings


def _rule_overprivileged_apps(result: ScanResult) -> List[Finding]:
    """Flag installed apps holding write or admin-level permissions (NHI5)."""
    admin_apps = []
    write_apps = []
    for app in result.installed_apps:
        if app.is_suspended:
            continue
        levels = set(app.permissions.values())
        if "admin" in levels:
            keys = sorted(k for k, v in app.permissions.items() if v == "admin")
            admin_apps.append((app.app_slug, keys))
        elif "write" in levels:
            keys = sorted(k for k, v in app.permissions.items() if v == "write")
            write_apps.append((app.app_slug, keys))

    findings: List[Finding] = []

    if admin_apps:
        findings.append(Finding(
            severity=Severity.HIGH,
            category="apps_admin_permissions",
            title=f"{len(admin_apps)} installed app(s) hold admin-level permissions",
            detail=(
                "These GitHub Apps are non-human identities granted admin-level access. "
                "A compromised or abandoned app with admin permissions can modify org or "
                "repo settings, manage access, and act autonomously without a human in the loop. "
                "Maps to NHI5 (Overprivileged NHI). Review whether each app genuinely "
                "requires admin and downgrade where possible."
            ),
            affected=[f"{slug} ({', '.join(keys)})" for slug, keys in admin_apps],
        ))

    if write_apps:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            category="apps_write_permissions",
            title=f"{len(write_apps)} installed app(s) hold write-level permissions",
            detail=(
                "These GitHub Apps can modify repository contents or settings. "
                "Confirm each app's write access matches its actual function. "
                "Maps to NHI5 (Overprivileged NHI)."
            ),
            affected=[f"{slug} ({', '.join(keys)})" for slug, keys in write_apps],
        ))

    return findings


def _rule_org_wide_apps(result: ScanResult) -> List[Finding]:
    """Flag installed apps that can access every repository (NHI5 — blast radius)."""
    flagged = [
        app.app_slug
        for app in result.installed_apps
        if app.has_org_wide_access and not app.is_suspended
    ]
    if not flagged:
        return []

    return [Finding(
        severity=Severity.MEDIUM,
        category="apps_org_wide_access",
        title=f"{len(flagged)} installed app(s) have access to all repositories",
        detail=(
            "These apps are installed with 'all repositories' selection rather than a "
            "scoped subset. The blast radius of a compromised or over-trusted app is the "
            "entire org. Where an app only needs a few repos, switch it to selected-repository "
            "access. Maps to NHI5 (Overprivileged NHI)."
        ),
        affected=flagged,
    )]


def _rule_suspended_apps(result: ScanResult) -> List[Finding]:
    """Flag suspended apps that are still installed (NHI1 — improper offboarding)."""
    flagged = [
        app.app_slug for app in result.installed_apps if app.is_suspended
    ]
    if not flagged:
        return []

    return [Finding(
        severity=Severity.LOW,
        category="apps_suspended_installed",
        title=f"{len(flagged)} suspended app(s) are still installed",
        detail=(
            "These apps are suspended but remain installed. A suspended app is a partially "
            "offboarded non-human identity — it can be re-enabled, and its presence signals "
            "incomplete cleanup. Uninstall apps that are no longer needed. "
            "Maps to NHI1 (Improper Offboarding)."
        ),
        affected=flagged,
    )]


# ---------------------------------------------------------------------------
# Non-human identity rules — deploy keys
# ---------------------------------------------------------------------------


def generate_deploy_key_findings(
    result: ScanResult, inactive_days: int = 90
) -> List[Finding]:
    """Governance rules for repository deploy keys (non-human credentials)."""
    findings: List[Finding] = []
    findings += _rule_read_write_deploy_keys(result)
    findings += _rule_stale_deploy_keys(result, inactive_days)
    return findings


def _rule_read_write_deploy_keys(result: ScanResult) -> List[Finding]:
    """Flag deploy keys with write access — they can push code (NHI5)."""
    flagged = [
        (k.repo_name, k.title) for k in result.deploy_keys if k.is_read_write
    ]
    if not flagged:
        return []

    return [Finding(
        severity=Severity.MEDIUM,
        category="deploy_keys_read_write",
        title=f"{len(flagged)} read-write deploy key(s) can push to repositories",
        detail=(
            "Deploy keys are SSH credentials tied to a repository, not a person. "
            "A read-write key can push code; if leaked, an attacker can commit directly. "
            "Use read-only deploy keys wherever push access isn't required. "
            "Maps to NHI5 (Overprivileged NHI)."
        ),
        affected=[f"{repo} ({title})" for repo, title in flagged],
    )]


def _rule_stale_deploy_keys(
    result: ScanResult, inactive_days: int
) -> List[Finding]:
    """Flag deploy keys unused for >= inactive_days (NHI1 — improper offboarding)."""
    now = datetime.now(timezone.utc)
    flagged = []
    for k in result.deploy_keys:
        ref = k.last_used or k.created_at
        if ref is None:
            continue
        if (now - ref).days >= inactive_days:
            label = (
                "never used" if k.last_used is None
                else f"last used {(now - k.last_used).days}d ago"
            )
            flagged.append((k.repo_name, k.title, label))

    if not flagged:
        return []

    return [Finding(
        severity=Severity.LOW,
        category="deploy_keys_stale",
        title=f"{len(flagged)} deploy key(s) appear stale or unused",
        detail=(
            f"These deploy keys have not been used in over {inactive_days} days (or never). "
            "Deploy keys are typically long-lived with no expiry, so forgotten ones linger as "
            "standing non-human credentials. Remove keys that are no longer needed. "
            "Maps to NHI1 (Improper Offboarding)."
        ),
        affected=[f"{repo} ({title}, {label})" for repo, title, label in flagged],
    )]


# ---------------------------------------------------------------------------
# Non-human identity rules — Actions secrets
# ---------------------------------------------------------------------------


def generate_secret_findings(
    result: ScanResult, stale_days: int = 365
) -> List[Finding]:
    """Governance rules for GitHub Actions secrets (long-lived credentials)."""
    return _rule_stale_secrets(result, stale_days)


def _rule_stale_secrets(result: ScanResult, stale_days: int) -> List[Finding]:
    """Flag Actions secrets not rotated in >= stale_days (NHI7 — long-lived secrets)."""
    now = datetime.now(timezone.utc)
    flagged = []
    for s in result.actions_secrets:
        days = s.days_since_rotated(now)
        if days is not None and days >= stale_days:
            loc = s.repo_name if s.level == "repo" else "org"
            flagged.append((loc, s.name, days))

    if not flagged:
        return []

    flagged.sort(key=lambda x: x[2], reverse=True)  # oldest first

    return [Finding(
        severity=Severity.MEDIUM,
        category="secrets_not_rotated",
        title=f"{len(flagged)} Actions secret(s) not rotated in {stale_days}+ days",
        detail=(
            "These GitHub Actions secrets have not been updated for a long time, with no "
            "evidence of rotation. Stored CI secrets are long-lived non-human credentials; "
            "the longer one goes unrotated, the larger the window if it was ever exposed. "
            "Rotate on a schedule. (gh-iga reads only secret names and timestamps, never "
            "values.) Maps to NHI7 (Long-Lived Secrets)."
        ),
        affected=[f"{loc}/{name} ({days}d)" for loc, name, days in flagged],
    )]


# ---------------------------------------------------------------------------
# Non-human identity rules — webhooks
# ---------------------------------------------------------------------------


def generate_webhook_findings(result: ScanResult) -> List[Finding]:
    """Governance rules for webhooks (third-party trust relationships)."""
    findings: List[Finding] = []
    findings += _rule_webhooks_no_secret(result)
    findings += _rule_webhooks_insecure_transport(result)
    return findings


def _webhook_label(w) -> str:
    loc = w.repo_name if w.level == "repo" else "org"
    return f"{loc} → {w.url}"


def _rule_webhooks_no_secret(result: ScanResult) -> List[Finding]:
    """Flag active webhooks with no signing secret (NHI3 — spoofable payloads)."""
    flagged = [w for w in result.webhooks if w.active and not w.has_secret]
    if not flagged:
        return []

    return [Finding(
        severity=Severity.MEDIUM,
        category="webhooks_no_secret",
        title=f"{len(flagged)} active webhook(s) have no signing secret",
        detail=(
            "Without a secret, the receiving service cannot verify that a payload genuinely "
            "came from GitHub — payloads can be spoofed or replayed against the endpoint. "
            "Configure a secret so deliveries are signed (HMAC). "
            "Maps to NHI3 (Vulnerable Third-Party NHI)."
        ),
        affected=[_webhook_label(w) for w in flagged],
    )]


def _rule_webhooks_insecure_transport(result: ScanResult) -> List[Finding]:
    """Flag active webhooks using http:// or with SSL verification disabled (NHI3)."""
    flagged = [w for w in result.webhooks if w.active and w.is_insecure_transport]
    if not flagged:
        return []

    return [Finding(
        severity=Severity.MEDIUM,
        category="webhooks_insecure_transport",
        title=f"{len(flagged)} active webhook(s) use insecure transport",
        detail=(
            "These webhooks deliver over cleartext http:// or with SSL verification disabled, "
            "so event payloads (which can include repo metadata) are exposed to interception "
            "or tampering in transit. Use https:// with SSL verification enabled. "
            "Maps to NHI3 (Vulnerable Third-Party NHI)."
        ),
        affected=[_webhook_label(w) for w in flagged],
    )]
