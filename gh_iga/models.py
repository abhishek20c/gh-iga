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
    findings: List[Finding] = field(default_factory=list)
    activity_checked: bool = False

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
