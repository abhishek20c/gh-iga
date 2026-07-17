"""Data models for gh-iga scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


# ---------------------------------------------------------------------------
# Permission helpers
# ---------------------------------------------------------------------------

PERMISSION_RANK = {
    "admin": 5,
    "maintain": 4,
    "write": 3,
    "triage": 2,
    "read": 1,
}


def has_write_or_above(permission: str) -> bool:
    return PERMISSION_RANK.get(permission, 0) >= PERMISSION_RANK["write"]


def highest_permission(permissions: List[str]) -> str:
    """Return the highest permission from a list."""
    if not permissions:
        return "read"
    return max(permissions, key=lambda p: PERMISSION_RANK.get(p, 0))


# ---------------------------------------------------------------------------
# Core models
# ---------------------------------------------------------------------------


@dataclass
class Collaborator:
    """A user's access to a single repository."""

    login: str
    permission: str  # admin | maintain | write | triage | read
    source: str      # "direct" or "team:<slug>"


@dataclass
class RepoPermission:
    """A repo name + permission level — used on Member and Team objects."""

    repo_name: str
    permission: str


@dataclass
class Repo:
    name: str
    full_name: str
    is_private: bool
    is_archived: bool
    description: Optional[str]
    # Populated during scanning: includes both direct and team-based collaborators
    collaborators: List[Collaborator] = field(default_factory=list)

    def unique_admins(self) -> List[str]:
        """Unique logins that have effective admin access (deduplicated across sources)."""
        seen: dict[str, int] = {}
        for c in self.collaborators:
            rank = PERMISSION_RANK.get(c.permission, 0)
            if c.login not in seen or rank > seen[c.login]:
                seen[c.login] = rank
        return [login for login, rank in seen.items() if rank == PERMISSION_RANK["admin"]]

    def effective_permission(self, login: str) -> Optional[str]:
        """Highest effective permission for a given login across all sources."""
        perms = [c.permission for c in self.collaborators if c.login == login]
        return highest_permission(perms) if perms else None


@dataclass
class Member:
    login: str
    name: Optional[str]
    role: str  # "owner" | "member"
    last_active: Optional[datetime] = None
    # Direct (non-team) repo access for this member
    direct_repo_access: List[RepoPermission] = field(default_factory=list)
    # Team slugs this member belongs to
    teams: List[str] = field(default_factory=list)

    @property
    def days_since_active(self) -> Optional[int]:
        if self.last_active is None:
            return None
        delta = datetime.now(self.last_active.tzinfo) - self.last_active
        return delta.days


@dataclass
class OutsideCollaborator:
    login: str
    repo_access: List[RepoPermission] = field(default_factory=list)

    def privileged_repos(self) -> List[RepoPermission]:
        return [r for r in self.repo_access if has_write_or_above(r.permission)]


@dataclass
class Team:
    name: str
    slug: str
    description: Optional[str]
    member_logins: List[str] = field(default_factory=list)
    repo_access: List[RepoPermission] = field(default_factory=list)


@dataclass
class InstalledApp:
    """A GitHub App installed on the account — a non-human identity.

    Each installation is an autonomous actor with its own permission set,
    independent of any human user. Installed on orgs and on personal accounts.
    """

    app_slug: str
    app_id: int
    installation_id: int
    permissions: dict[str, str]        # e.g. {"contents": "read", "administration": "write"}
    repository_selection: str          # "all" | "selected"
    events: List[str] = field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    suspended_at: Optional[datetime] = None

    @property
    def is_suspended(self) -> bool:
        return self.suspended_at is not None

    @property
    def has_org_wide_access(self) -> bool:
        """True if the app can access every repo, not a selected subset."""
        return self.repository_selection == "all"

    def privileged_permissions(self) -> List[str]:
        """Permission keys granted at write or admin level."""
        return [k for k, v in self.permissions.items() if v in ("write", "admin")]


@dataclass
class DeployKey:
    """An SSH deploy key on a repository — a non-human credential.

    Grants Git access to a single repo, independent of any user account.
    Typically long-lived with no expiry (NHI7); read-write keys can push (NHI5);
    unused keys are a frequent offboarding gap (NHI1).
    """

    key_id: int
    title: str
    repo_name: str
    read_only: bool
    created_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    added_by: Optional[str] = None

    @property
    def is_read_write(self) -> bool:
        return not self.read_only


@dataclass
class ActionsSecret:
    """A GitHub Actions secret — a stored long-lived credential (NHI7).

    GitHub exposes only the name and timestamps, never the value. An old
    ``updated_at`` is the only available signal that a secret has not been
    rotated.
    """

    name: str
    level: str                          # "repo" | "org"
    repo_name: Optional[str] = None     # set for repo-level secrets
    visibility: Optional[str] = None    # org-level: "all" | "private" | "selected"
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def days_since_rotated(self, now: datetime) -> Optional[int]:
        """Days since the secret was last created/updated, or None if unknown."""
        ref = self.updated_at or self.created_at
        return (now - ref).days if ref else None


@dataclass
class Webhook:
    """A repo- or org-level webhook — an outbound trust relationship to a third party (NHI3)."""

    hook_id: int
    level: str                          # "repo" | "org"
    url: str
    active: bool
    has_secret: bool                    # whether a signing secret is configured
    insecure_ssl: bool                  # SSL verification disabled (config.insecure_ssl == "1")
    repo_name: Optional[str] = None
    events: List[str] = field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @property
    def is_http(self) -> bool:
        return self.url.lower().startswith("http://")

    @property
    def is_insecure_transport(self) -> bool:
        """Cleartext URL or SSL verification disabled."""
        return self.is_http or self.insecure_ssl


@dataclass
class WorkflowPermissions:
    """Default GITHUB_TOKEN permissions for an org or repo's Actions workflows (NHI5).

    The GITHUB_TOKEN is the automatic non-human credential every workflow run uses.
    A read-write default grants more than most workflows need.
    """

    level: str                          # "repo" | "org"
    default_permissions: str            # "read" | "write"
    can_approve_pull_requests: bool
    repo_name: Optional[str] = None

    @property
    def is_write_default(self) -> bool:
        return self.default_permissions == "write"


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class Severity:
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Finding:
    severity: str       # Severity.HIGH / MEDIUM / LOW
    category: str       # machine-readable category key
    title: str          # one-line human summary
    detail: str         # explanation + governance rationale
    affected: List[str] = field(default_factory=list)  # list of affected logins/repos

    @property
    def severity_label(self) -> str:
        return self.severity.upper()

    @property
    def affected_count(self) -> int:
        return len(self.affected)


# ---------------------------------------------------------------------------
# Scan completeness
# ---------------------------------------------------------------------------


@dataclass
class CoverageIssue:
    """One optional inventory endpoint that could not be inspected."""

    scope: str
    reason: str
    status_code: Optional[int] = None


@dataclass
class ScanCoverage:
    """Completeness information for one inventory area."""

    area: str
    label: str
    applicable: bool = True
    attempted: int = 0
    succeeded: int = 0
    issues: List[CoverageIssue] = field(default_factory=list)

    def record_success(self) -> None:
        self.attempted += 1
        self.succeeded += 1

    def record_skip(
        self, scope: str, reason: str, status_code: Optional[int] = None
    ) -> None:
        self.attempted += 1
        self.issues.append(
            CoverageIssue(scope=scope, reason=reason, status_code=status_code)
        )

    @property
    def skipped(self) -> int:
        return len(self.issues)

    @property
    def status(self) -> str:
        if not self.applicable:
            return "not_applicable"
        if self.issues and self.succeeded:
            return "partial"
        if self.issues:
            return "skipped"
        return "complete"


# ---------------------------------------------------------------------------
# Top-level result
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    org: str
    scanned_at: datetime
    members: List[Member]
    outside_collaborators: List[OutsideCollaborator]
    repos: List[Repo]
    teams: List[Team]
    installed_apps: List[InstalledApp] = field(default_factory=list)
    deploy_keys: List[DeployKey] = field(default_factory=list)
    actions_secrets: List[ActionsSecret] = field(default_factory=list)
    webhooks: List[Webhook] = field(default_factory=list)
    workflow_permissions: List[WorkflowPermissions] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    activity_checked: bool = False
    coverage: List[ScanCoverage] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Convenience slices
    # ------------------------------------------------------------------

    @property
    def high_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def medium_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == Severity.MEDIUM]

    @property
    def low_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == Severity.LOW]

    @property
    def owners(self) -> List[Member]:
        return [m for m in self.members if m.role == "owner"]

    @property
    def active_repos(self) -> List[Repo]:
        return [r for r in self.repos if not r.is_archived]

    @property
    def incomplete_coverage(self) -> List[ScanCoverage]:
        return [c for c in self.coverage if c.status in ("partial", "skipped")]

    @property
    def scan_status(self) -> str:
        return "partial" if self.incomplete_coverage else "complete"
