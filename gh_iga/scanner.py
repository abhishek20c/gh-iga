"""GitHub REST API client and org scanner."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from dateutil import parser as dateutil_parser
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from .models import (
    ActionsSecret,
    Collaborator,
    DeployKey,
    InstalledApp,
    Member,
    OutsideCollaborator,
    Repo,
    RepoPermission,
    ScanCoverage,
    ScanResult,
    Team,
    Webhook,
    WorkflowPermissions,
)

_GITHUB_API = "https://api.github.com"
_ACCEPT = "application/vnd.github+json"
_API_VERSION = "2022-11-28"

_COVERAGE_AREAS = {
    "installed_apps": "Installed GitHub Apps",
    "deploy_keys": "Deploy keys",
    "actions_secrets": "Actions secrets",
    "webhooks": "Webhooks",
    "workflow_permissions": "Workflow permissions",
}


# ---------------------------------------------------------------------------
# Permission mapping helpers
# ---------------------------------------------------------------------------


def _permission_from_dict(perms: Dict[str, bool]) -> str:
    """Map a GitHub permissions dict → canonical permission string."""
    if perms.get("admin"):
        return "admin"
    if perms.get("maintain"):
        return "maintain"
    if perms.get("push"):
        return "write"
    if perms.get("triage"):
        return "triage"
    return "read"


def _resolve_permission(obj: Dict[str, Any]) -> str:
    """Extract permission from a GitHub API response object.

    Prefers the ``role_name`` field (available with the v3 JSON Accept header)
    and falls back to the legacy ``permissions`` dict.
    """
    role = obj.get("role_name")
    if role:
        # GitHub uses "write" internally but may return "push" in some endpoints
        return "write" if role == "push" else role
    return _permission_from_dict(obj.get("permissions", {}))


def _parse_datetime(val: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 string from the API into a datetime, or None."""
    return dateutil_parser.parse(val) if val else None


def _parse_installation(raw: Dict[str, Any]) -> InstalledApp:
    """Map a raw GitHub App installation object → :class:`InstalledApp`."""
    return InstalledApp(
        app_slug=raw.get("app_slug") or "",
        app_id=raw.get("app_id") or 0,
        installation_id=raw.get("id") or 0,
        permissions=raw.get("permissions") or {},
        repository_selection=raw.get("repository_selection") or "selected",
        events=raw.get("events") or [],
        created_at=_parse_datetime(raw.get("created_at")),
        updated_at=_parse_datetime(raw.get("updated_at")),
        suspended_at=_parse_datetime(raw.get("suspended_at")),
    )


def _parse_deploy_key(raw: Dict[str, Any], repo_name: str) -> DeployKey:
    """Map a raw deploy-key object → :class:`DeployKey`."""
    return DeployKey(
        key_id=raw.get("id") or 0,
        title=raw.get("title") or "",
        repo_name=repo_name,
        read_only=bool(raw.get("read_only", True)),
        created_at=_parse_datetime(raw.get("created_at")),
        last_used=_parse_datetime(raw.get("last_used")),
        added_by=raw.get("added_by"),
    )


def _parse_actions_secret(
    raw: Dict[str, Any], level: str, repo_name: Optional[str] = None
) -> ActionsSecret:
    """Map a raw Actions-secret object → :class:`ActionsSecret`."""
    return ActionsSecret(
        name=raw.get("name") or "",
        level=level,
        repo_name=repo_name,
        visibility=raw.get("visibility"),
        created_at=_parse_datetime(raw.get("created_at")),
        updated_at=_parse_datetime(raw.get("updated_at")),
    )


def _parse_webhook(raw: Dict[str, Any], level: str, repo_name: Optional[str] = None) -> Webhook:
    """Map a raw webhook object → :class:`Webhook`.

    GitHub returns ``config.secret`` masked (``********``) when a secret is set,
    and omits the field otherwise — so presence indicates a configured secret.
    """
    config = raw.get("config") or {}
    return Webhook(
        hook_id=raw.get("id") or 0,
        level=level,
        repo_name=repo_name,
        url=config.get("url") or "",
        active=bool(raw.get("active", True)),
        has_secret=bool(config.get("secret")),
        insecure_ssl=str(config.get("insecure_ssl", "0")) == "1",
        events=raw.get("events") or [],
        created_at=_parse_datetime(raw.get("created_at")),
        updated_at=_parse_datetime(raw.get("updated_at")),
    )


def _parse_workflow_permissions(
    raw: Dict[str, Any], level: str, repo_name: Optional[str] = None
) -> WorkflowPermissions:
    """Map a raw workflow-permissions settings object → :class:`WorkflowPermissions`."""
    return WorkflowPermissions(
        level=level,
        repo_name=repo_name,
        default_permissions=raw.get("default_workflow_permissions") or "read",
        can_approve_pull_requests=bool(raw.get("can_approve_pull_request_reviews", False)),
    )


# ---------------------------------------------------------------------------
# GitHub REST client
# ---------------------------------------------------------------------------


class GitHubClient:
    """Thin authenticated wrapper around the GitHub REST API."""

    def __init__(self, token: str):
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": _ACCEPT,
                "X-GitHub-Api-Version": _API_VERSION,
            }
        )

    # ------------------------------------------------------------------
    # Low-level helpers
    # ------------------------------------------------------------------

    def _get(self, path: str, params: Optional[Dict] = None) -> Any:
        url = f"{_GITHUB_API}{path}"
        resp = self._session.get(url, params=params, timeout=30)
        self._handle_rate_limit(resp)
        resp.raise_for_status()
        return resp.json()

    def _paginate(self, path: str, params: Optional[Dict] = None) -> List[Any]:
        """Collect all pages for a list endpoint."""
        params = dict(params or {})
        params["per_page"] = 100
        page = 1
        results: List[Any] = []
        while True:
            params["page"] = page
            data = self._get(path, params)
            if not data:
                break
            results.extend(data)
            if len(data) < 100:
                break
            page += 1
        return results

    def _paginate_wrapped(self, path: str, key: str, params: Optional[Dict] = None) -> List[Any]:
        """Collect all pages for an endpoint that wraps its list in an object.

        Some endpoints (e.g. ``/orgs/{org}/installations``) return
        ``{"total_count": N, "<key>": [...]}`` rather than a bare array.
        """
        params = dict(params or {})
        params["per_page"] = 100
        page = 1
        results: List[Any] = []
        while True:
            params["page"] = page
            data = self._get(path, params)
            items = data.get(key, []) if isinstance(data, dict) else []
            if not items:
                break
            results.extend(items)
            if len(items) < 100:
                break
            page += 1
        return results

    @staticmethod
    def _handle_rate_limit(resp: requests.Response) -> None:
        """Sleep if we are close to the rate limit."""
        try:
            remaining = int(resp.headers.get("X-RateLimit-Remaining", 100))
        except ValueError:
            return
        if remaining < 5:
            reset_ts = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
            sleep_for = max(1, reset_ts - int(time.time())) + 2
            time.sleep(min(sleep_for, 120))

    # ------------------------------------------------------------------
    # API methods
    # ------------------------------------------------------------------

    def get_org(self, org: str) -> Dict:
        return self._get(f"/orgs/{org}")

    def get_org_members(self, org: str) -> Tuple[List[Dict], List[Dict]]:
        """Return (owners, regular_members) as two separate lists."""
        owners = self._paginate(f"/orgs/{org}/members", {"role": "admin"})
        members = self._paginate(f"/orgs/{org}/members", {"role": "member"})
        return owners, members

    def get_outside_collaborators(self, org: str) -> List[Dict]:
        return self._paginate(f"/orgs/{org}/outside_collaborators")

    def get_repos(self, org: str) -> List[Dict]:
        return self._paginate(f"/orgs/{org}/repos", {"type": "all"})

    def get_repo_collaborators(self, org: str, repo: str) -> List[Dict]:
        """Direct (non-team) collaborators with permission info."""
        return self._paginate(f"/repos/{org}/{repo}/collaborators", {"affiliation": "direct"})

    def get_repo_deploy_keys(self, owner: str, repo: str) -> List[Dict]:
        """SSH deploy keys on a repo (per-repo non-human credentials).

        Requires admin permission on the repo; callers should handle HTTPError
        per-repo and skip repos where the token lacks admin.
        """
        return self._paginate(f"/repos/{owner}/{repo}/keys")

    def get_repo_actions_secrets(self, owner: str, repo: str) -> List[Dict]:
        """GitHub Actions secrets on a repo (names + timestamps; never values).

        Requires admin on the repo; handle HTTPError per-repo.
        """
        return self._paginate_wrapped(f"/repos/{owner}/{repo}/actions/secrets", "secrets")

    def get_org_actions_secrets(self, org: str) -> List[Dict]:
        """Org-level GitHub Actions secrets (names + timestamps; never values)."""
        return self._paginate_wrapped(f"/orgs/{org}/actions/secrets", "secrets")

    def get_org_webhooks(self, org: str) -> List[Dict]:
        """Org-level webhooks. Requires admin:org."""
        return self._paginate(f"/orgs/{org}/hooks")

    def get_repo_webhooks(self, owner: str, repo: str) -> List[Dict]:
        """Repo-level webhooks. Requires admin on the repo; handle HTTPError per-repo."""
        return self._paginate(f"/repos/{owner}/{repo}/hooks")

    def get_org_workflow_permissions(self, org: str) -> Dict:
        """Org default GITHUB_TOKEN workflow permissions. Requires admin:org."""
        return self._get(f"/orgs/{org}/actions/permissions/workflow")

    def get_repo_workflow_permissions(self, owner: str, repo: str) -> Dict:
        """Repo default GITHUB_TOKEN workflow permissions. Requires admin on the repo."""
        return self._get(f"/repos/{owner}/{repo}/actions/permissions/workflow")

    def get_teams(self, org: str) -> List[Dict]:
        return self._paginate(f"/orgs/{org}/teams")

    def get_org_app_installations(self, org: str) -> List[Dict]:
        """GitHub Apps installed on the org (each is a non-human identity).

        Returns the raw installation objects; the scanner maps them to
        :class:`~gh_iga.models.InstalledApp`. Requires the token to have
        org-admin visibility (``admin:org`` / org owner).
        """
        return self._paginate_wrapped(f"/orgs/{org}/installations", "installations")

    def get_team_members(self, org: str, team_slug: str) -> List[Dict]:
        return self._paginate(f"/orgs/{org}/teams/{team_slug}/members")

    def get_team_repos(self, org: str, team_slug: str) -> List[Dict]:
        return self._paginate(f"/orgs/{org}/teams/{team_slug}/repos")

    def get_authenticated_user(self) -> Dict:
        """Return the authenticated user's profile."""
        return self._get("/user")

    def get_user_repos(self) -> List[Dict]:
        """All repos owned by the authenticated user (including private)."""
        return self._paginate("/user/repos", {"type": "owner", "sort": "updated"})

    def get_user_last_event_in_org(self, login: str, org: str) -> Optional[datetime]:
        """Return the datetime of the user's most recent event in the org, or None."""
        try:
            # /users/{login}/events/orgs/{org} requires the authenticated user
            # to be an org member — which is true when scanning with a valid org token.
            events = self._get(f"/users/{login}/events/orgs/{org}", {"per_page": 1})
            if events:
                return dateutil_parser.parse(events[0]["created_at"])
        except Exception:
            # Fall back to public events if org events fail (e.g. non-member token)
            try:
                events = self._get(f"/users/{login}/events", {"per_page": 1})
                if events:
                    return dateutil_parser.parse(events[0]["created_at"])
            except Exception:
                pass
        return None


# ---------------------------------------------------------------------------
# Main scan orchestrator
# ---------------------------------------------------------------------------


def _coverage_map(*, installed_apps_applicable: bool = True) -> Dict[str, ScanCoverage]:
    coverage = {
        area: ScanCoverage(area=area, label=label) for area, label in _COVERAGE_AREAS.items()
    }
    coverage["installed_apps"].applicable = installed_apps_applicable
    return coverage


def _record_optional_http_error(
    coverage: ScanCoverage,
    scope: str,
    exc: requests.HTTPError,
) -> None:
    """Record expected access gaps; propagate auth, rate-limit, and server failures."""
    response = exc.response
    status = response.status_code if response is not None else None
    remaining = response.headers.get("X-RateLimit-Remaining") if response is not None else None

    if status == 403 and remaining == "0":
        raise exc
    if status == 403:
        coverage.record_skip(scope, "insufficient_permission", status)
        return
    if status == 404:
        coverage.record_skip(scope, "not_found_or_inaccessible", status)
        return
    raise exc


def scan_org(
    org: str,
    token: str,
    *,
    inactive_days: int = 90,
    check_activity: bool = True,
    console: Optional[Console] = None,
) -> ScanResult:
    """Scan a GitHub org and return a :class:`ScanResult`.

    Args:
        org: GitHub org login (e.g. ``"kubernetes"``).
        token: Personal access token with ``read:org`` and ``repo`` scopes.
        inactive_days: Days of inactivity threshold (used by rules, not scanning).
        check_activity: Whether to fetch last-event timestamps for each member.
                        Disable with ``--no-activity`` for faster scans of large orgs.
        console: Rich Console for progress output; creates one if not provided.
    """
    if console is None:
        console = Console()

    client = GitHubClient(token)

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )

    with progress:

        # ----------------------------------------------------------------
        # 1. Org info (validate token + org exist)
        # ----------------------------------------------------------------
        t = progress.add_task("Validating org…", total=None)
        org_info = client.get_org(org)  # raises HTTPError if 404/401
        progress.update(
            t, description=f"Org: [bold]{org_info['login']}[/bold] ✓", completed=1, total=1
        )

        # ----------------------------------------------------------------
        # 2. Members
        # ----------------------------------------------------------------
        t = progress.add_task("Fetching members…", total=None)
        owners_raw, regular_raw = client.get_org_members(org)

        members: List[Member] = []
        for u in owners_raw:
            members.append(Member(login=u["login"], name=u.get("name"), role="owner"))
        for u in regular_raw:
            members.append(Member(login=u["login"], name=u.get("name"), role="member"))

        member_map: Dict[str, Member] = {m.login: m for m in members}
        progress.update(t, description=f"Members: {len(members)} ✓", completed=1, total=1)

        # ----------------------------------------------------------------
        # 3. Outside collaborators
        # ----------------------------------------------------------------
        t = progress.add_task("Fetching outside collaborators…", total=None)
        outside_raw = client.get_outside_collaborators(org)
        outside_map: Dict[str, OutsideCollaborator] = {
            u["login"]: OutsideCollaborator(login=u["login"]) for u in outside_raw
        }
        progress.update(
            t,
            description=f"Outside collaborators: {len(outside_map)} ✓",
            completed=1,
            total=1,
        )

        # ----------------------------------------------------------------
        # 4. Repos + direct collaborators
        # ----------------------------------------------------------------
        t_repos = progress.add_task("Fetching repositories…", total=None)
        repos_raw = client.get_repos(org)
        progress.update(
            t_repos,
            description=f"Scanning {len(repos_raw)} repos…",
            completed=0,
            total=len(repos_raw),
        )

        repos: List[Repo] = []
        deploy_keys: List[DeployKey] = []
        actions_secrets: List[ActionsSecret] = []
        webhooks: List[Webhook] = []
        workflow_permissions: List[WorkflowPermissions] = []
        coverage = _coverage_map()

        # Org-level default workflow (GITHUB_TOKEN) permissions (once)
        try:
            workflow_permissions.append(
                _parse_workflow_permissions(client.get_org_workflow_permissions(org), "org")
            )
            coverage["workflow_permissions"].record_success()
        except requests.HTTPError as exc:
            _record_optional_http_error(coverage["workflow_permissions"], "org", exc)

        # Org-level Actions secrets (once, not per-repo)
        try:
            for s in client.get_org_actions_secrets(org):
                actions_secrets.append(_parse_actions_secret(s, "org"))
            coverage["actions_secrets"].record_success()
        except requests.HTTPError as exc:
            _record_optional_http_error(coverage["actions_secrets"], "org", exc)

        # Org-level webhooks (once)
        try:
            for h in client.get_org_webhooks(org):
                webhooks.append(_parse_webhook(h, "org"))
            coverage["webhooks"].record_success()
        except requests.HTTPError as exc:
            _record_optional_http_error(coverage["webhooks"], "org", exc)

        for repo_raw in repos_raw:
            repo_name: str = repo_raw["name"]

            collabs_raw = client.get_repo_collaborators(org, repo_name)
            collaborators: List[Collaborator] = []

            for c in collabs_raw:
                login: str = c["login"]
                perm = _resolve_permission(c)
                collaborators.append(Collaborator(login=login, permission=perm, source="direct"))

                # Back-populate member / outside-collab objects
                if login in member_map:
                    member_map[login].direct_repo_access.append(
                        RepoPermission(repo_name=repo_name, permission=perm)
                    )
                elif login in outside_map:
                    outside_map[login].repo_access.append(
                        RepoPermission(repo_name=repo_name, permission=perm)
                    )

            # Deploy keys (non-human credentials) — needs admin on the repo
            try:
                for k in client.get_repo_deploy_keys(org, repo_name):
                    deploy_keys.append(_parse_deploy_key(k, repo_name))
                coverage["deploy_keys"].record_success()
            except requests.HTTPError as exc:
                _record_optional_http_error(coverage["deploy_keys"], f"repo:{repo_name}", exc)

            # Repo-level Actions secrets — needs admin on the repo
            try:
                for s in client.get_repo_actions_secrets(org, repo_name):
                    actions_secrets.append(_parse_actions_secret(s, "repo", repo_name))
                coverage["actions_secrets"].record_success()
            except requests.HTTPError as exc:
                _record_optional_http_error(coverage["actions_secrets"], f"repo:{repo_name}", exc)

            # Repo-level webhooks — needs admin on the repo
            try:
                for h in client.get_repo_webhooks(org, repo_name):
                    webhooks.append(_parse_webhook(h, "repo", repo_name))
                coverage["webhooks"].record_success()
            except requests.HTTPError as exc:
                _record_optional_http_error(coverage["webhooks"], f"repo:{repo_name}", exc)

            # Repo-level default workflow (GITHUB_TOKEN) permissions
            try:
                workflow_permissions.append(
                    _parse_workflow_permissions(
                        client.get_repo_workflow_permissions(org, repo_name), "repo", repo_name
                    )
                )
                coverage["workflow_permissions"].record_success()
            except requests.HTTPError as exc:
                _record_optional_http_error(
                    coverage["workflow_permissions"], f"repo:{repo_name}", exc
                )

            repos.append(
                Repo(
                    name=repo_name,
                    full_name=repo_raw["full_name"],
                    is_private=repo_raw.get("private", False),
                    is_archived=repo_raw.get("archived", False),
                    description=repo_raw.get("description"),
                    collaborators=collaborators,
                )
            )
            progress.advance(t_repos)

        progress.update(
            t_repos,
            description=f"Repos scanned: {len(repos)} ✓ ({len(deploy_keys)} deploy keys)",
        )

        # ----------------------------------------------------------------
        # 5. Teams + team repo permissions
        # ----------------------------------------------------------------
        t = progress.add_task("Fetching teams…", total=None)
        teams_raw = client.get_teams(org)
        repo_by_name: Dict[str, Repo] = {r.name: r for r in repos}

        teams: List[Team] = []
        for team_raw in teams_raw:
            slug: str = team_raw["slug"]
            team_members_raw = client.get_team_members(org, slug)
            team_repos_raw = client.get_team_repos(org, slug)

            member_logins = [m["login"] for m in team_members_raw]

            # Back-populate teams onto Member objects
            for login in member_logins:
                if login in member_map:
                    member_map[login].teams.append(slug)

            team_repo_access: List[RepoPermission] = []
            for tr in team_repos_raw:
                rname: str = tr["name"]
                perm = _resolve_permission(tr)
                team_repo_access.append(RepoPermission(repo_name=rname, permission=perm))

                # Inject team-based collaborators into each Repo
                if rname in repo_by_name:
                    for login in member_logins:
                        repo_by_name[rname].collaborators.append(
                            Collaborator(
                                login=login,
                                permission=perm,
                                source=f"team:{slug}",
                            )
                        )

            teams.append(
                Team(
                    name=team_raw["name"],
                    slug=slug,
                    description=team_raw.get("description"),
                    member_logins=member_logins,
                    repo_access=team_repo_access,
                )
            )

        progress.update(t, description=f"Teams: {len(teams)} ✓", completed=1, total=1)

        # ----------------------------------------------------------------
        # 6. Installed GitHub Apps (non-human identities)
        # ----------------------------------------------------------------
        t = progress.add_task("Fetching installed apps…", total=None)
        installed_apps: List[InstalledApp] = []
        try:
            apps_raw = client.get_org_app_installations(org)
            installed_apps = [_parse_installation(a) for a in apps_raw]
            coverage["installed_apps"].record_success()
            progress.update(
                t, description=f"Installed apps: {len(installed_apps)} ✓", completed=1, total=1
            )
        except requests.HTTPError as exc:
            # Requires org-admin visibility; skip gracefully if the token lacks it.
            _record_optional_http_error(coverage["installed_apps"], "org", exc)
            progress.update(
                t, description="Installed apps: skipped (needs org admin) ✓", completed=1, total=1
            )

        # ----------------------------------------------------------------
        # 7. Activity (optional — one API call per member)
        # ----------------------------------------------------------------
        activity_checked = False
        if check_activity:
            t = progress.add_task("Checking member activity…", total=len(members))
            for member in members:
                member.last_active = client.get_user_last_event_in_org(member.login, org)
                progress.advance(t)
            activity_checked = True
            progress.update(t, description="Activity checked ✓")

    return ScanResult(
        org=org,
        scanned_at=datetime.now(timezone.utc),
        members=members,
        outside_collaborators=list(outside_map.values()),
        repos=repos,
        teams=teams,
        installed_apps=installed_apps,
        deploy_keys=deploy_keys,
        actions_secrets=actions_secrets,
        webhooks=webhooks,
        workflow_permissions=workflow_permissions,
        activity_checked=activity_checked,
        coverage=list(coverage.values()),
    )


# ---------------------------------------------------------------------------
# User (personal account) scanner
# ---------------------------------------------------------------------------


def scan_user(
    token: str,
    *,
    console: Optional[Console] = None,
) -> ScanResult:
    """Scan all repos owned by the authenticated user.

    This is the personal-account equivalent of :func:`scan_org`.
    It lists every repo you own, fetches collaborators for each, and
    identifies anyone who has been granted access — and at what level.

    Args:
        token: Personal access token with ``repo`` scope.
        console: Rich Console for progress output.
    """
    if console is None:
        console = Console()

    client = GitHubClient(token)

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )

    with progress:

        # ----------------------------------------------------------------
        # 1. Identify who we are
        # ----------------------------------------------------------------
        t = progress.add_task("Identifying user…", total=None)
        me = client.get_authenticated_user()
        username: str = me["login"]
        progress.update(t, description=f"User: [bold]{username}[/bold] ✓", completed=1, total=1)

        # ----------------------------------------------------------------
        # 2. Repos
        # ----------------------------------------------------------------
        t_repos = progress.add_task("Fetching your repos…", total=None)
        repos_raw = client.get_user_repos()
        progress.update(
            t_repos,
            description=f"Scanning {len(repos_raw)} repos…",
            completed=0,
            total=len(repos_raw),
        )

        repos: List[Repo] = []
        deploy_keys: List[DeployKey] = []
        actions_secrets: List[ActionsSecret] = []
        webhooks: List[Webhook] = []
        workflow_permissions: List[WorkflowPermissions] = []
        outside_map: Dict[str, OutsideCollaborator] = {}
        coverage = _coverage_map(installed_apps_applicable=False)

        for repo_raw in repos_raw:
            repo_name: str = repo_raw["name"]
            collaborators: List[Collaborator] = []

            collabs_raw = client.get_repo_collaborators(username, repo_name)
            for c in collabs_raw:
                login: str = c["login"]
                if login == username:
                    continue  # skip yourself — you're always admin on your own repos

                perm = _resolve_permission(c)
                collaborators.append(Collaborator(login=login, permission=perm, source="direct"))

                # Track as outside collaborator
                if login not in outside_map:
                    outside_map[login] = OutsideCollaborator(login=login)
                outside_map[login].repo_access.append(
                    RepoPermission(repo_name=repo_name, permission=perm)
                )

            # Deploy keys (non-human credentials) on your own repos
            try:
                for k in client.get_repo_deploy_keys(username, repo_name):
                    deploy_keys.append(_parse_deploy_key(k, repo_name))
                coverage["deploy_keys"].record_success()
            except requests.HTTPError as exc:
                _record_optional_http_error(coverage["deploy_keys"], f"repo:{repo_name}", exc)

            # Repo-level Actions secrets
            try:
                for s in client.get_repo_actions_secrets(username, repo_name):
                    actions_secrets.append(_parse_actions_secret(s, "repo", repo_name))
                coverage["actions_secrets"].record_success()
            except requests.HTTPError as exc:
                _record_optional_http_error(coverage["actions_secrets"], f"repo:{repo_name}", exc)

            # Repo-level webhooks
            try:
                for h in client.get_repo_webhooks(username, repo_name):
                    webhooks.append(_parse_webhook(h, "repo", repo_name))
                coverage["webhooks"].record_success()
            except requests.HTTPError as exc:
                _record_optional_http_error(coverage["webhooks"], f"repo:{repo_name}", exc)

            # Repo-level default workflow (GITHUB_TOKEN) permissions
            try:
                workflow_permissions.append(
                    _parse_workflow_permissions(
                        client.get_repo_workflow_permissions(username, repo_name), "repo", repo_name
                    )
                )
                coverage["workflow_permissions"].record_success()
            except requests.HTTPError as exc:
                _record_optional_http_error(
                    coverage["workflow_permissions"], f"repo:{repo_name}", exc
                )

            repos.append(
                Repo(
                    name=repo_name,
                    full_name=repo_raw["full_name"],
                    is_private=repo_raw.get("private", False),
                    is_archived=repo_raw.get("archived", False),
                    description=repo_raw.get("description"),
                    collaborators=collaborators,
                )
            )
            progress.advance(t_repos)

        progress.update(
            t_repos,
            description=f"Repos scanned: {len(repos)} ✓ ({len(deploy_keys)} deploy keys)",
        )

    # Represent the owner as a single "owner" member for report consistency
    owner_member = Member(login=username, name=me.get("name"), role="owner")

    # Note: app inventory is org-only. GitHub exposes no PAT-accessible endpoint
    # to list GitHub Apps installed on (or authorized by) a personal account —
    # /user/installations requires a GitHub App user-access-token, not a PAT.
    return ScanResult(
        org=username,  # reuse org field as the account name
        scanned_at=datetime.now(timezone.utc),
        members=[owner_member],
        outside_collaborators=list(outside_map.values()),
        repos=repos,
        teams=[],
        deploy_keys=deploy_keys,
        actions_secrets=actions_secrets,
        webhooks=webhooks,
        workflow_permissions=workflow_permissions,
        activity_checked=False,
        coverage=list(coverage.values()),
    )
