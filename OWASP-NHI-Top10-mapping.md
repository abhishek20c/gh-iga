# gh-iga ↔ OWASP Non-Human Identities Top 10 (2025) Mapping

This document maps `gh-iga` detection checks to the [OWASP Non-Human Identities Top 10](https://owasp.org/www-project-non-human-identities-top-10/) risk categories, for GitHub organization environments.

`gh-iga` is a read-only, MIT-licensed scanner. It requires only read scopes (`repo`, `read:org`, and `admin:org` for the GitHub App inventory), writes all output locally, and sends no telemetry. As of v0.2 it detects non-human identities directly: it inventories the GitHub Apps installed on an org and flags the risky ones — alongside its original human-identity governance checks.

## Coverage summary

| OWASP Risk | Risk Name | gh-iga detection | Status |
|---|---|---|---|
| **NHI1** | Improper Offboarding | Inactive privileged accounts, orphaned members, suspended-but-installed apps, stale deploy keys | ✅ Shipped |
| **NHI3** | Vulnerable Third-Party NHI | GitHub App inventory; apps with org-wide repo access | ✅ Shipped (v0.2) |
| **NHI5** | Overprivileged NHI | Admin sprawl, over-permissioned repos, privileged outside collaborators; apps with admin/write permissions; read-write deploy keys | ✅ Shipped |
| **NHI7** | Long-Lived Secrets | Deploy key inventory (read-write/stale); Actions secrets inventory (unrotated) | ✅ Shipped (v0.4) |
| **NHI10** | Human Use of NHI | Service/shared-account detection | 🔜 Roadmap |

The GitHub App inventory is **org-scan only** — GitHub exposes no PAT-accessible API to enumerate apps on a personal account. Deploy key inventory works on both org and personal-account scans (per-repo, requires admin on the repo).

## Detailed mapping

### NHI1 — Improper Offboarding

> *Risk: identities (human or machine) that retain access after they should have been deprovisioned.*

| gh-iga check | Severity | What it detects |
|---|---|---|
| `inactive_privileged` | High | Accounts with no recorded org activity for ≥ N days (default 90) that still hold write/admin. |
| `orphaned_members` | Medium | Non-owner members on no team with no direct repo access — often incomplete on/offboarding. |
| `apps_suspended_installed` | Low | GitHub Apps that are suspended but still installed — a partially offboarded NHI that can be re-enabled. |
| `deploy_keys_stale` | Low | Deploy keys unused for ≥ N days (or never) — forgotten standing credentials. |

### NHI3 — Vulnerable Third-Party NHI

> *Risk: third-party machine identities (integrations, apps) with excessive or unmonitored access.*

| gh-iga check | Severity | What it detects |
|---|---|---|
| GitHub App inventory | — | Every GitHub App installed on the org is enumerated with its permissions, repository scope, and status. Each installed app is a third-party NHI with autonomous access. |
| `apps_org_wide_access` | Medium | Apps installed with "all repositories" selection — the blast radius of a compromised app is the entire org. |

**Sample finding:**

```json
{
  "severity": "medium",
  "category": "apps_org_wide_access",
  "title": "3 installed app(s) have access to all repositories",
  "affected": ["ci-deploy-bot", "coverage-app", "legacy-integration"]
}
```

### NHI5 — Overprivileged NHI

> *Risk: identities granted broader access than their function requires.*

| gh-iga check | Severity | What it detects |
|---|---|---|
| `admin_sprawl` | High | Accounts holding admin on ≥ N active repos (default 5). |
| `privileged_outside_collaborators` | High | External (non-member) accounts with write/admin — bypass org SSO/2FA. |
| `apps_admin_permissions` | High | Installed apps holding admin-level permissions. |
| `apps_write_permissions` | Medium | Installed apps holding write-level permissions. |
| `deploy_keys_read_write` | Medium | Deploy keys with write access — a non-human credential that can push code. |
| `over_permissioned_repos` | Medium | Repos with more than N unique admins (default 3). |
| `direct_access_candidates` | Low | Direct grants redundant with team-based access. |

**Sample finding:**

```json
{
  "severity": "high",
  "category": "apps_admin_permissions",
  "title": "1 installed app(s) hold admin-level permissions",
  "affected": ["legacy-integration (administration)"]
}
```

### NHI7 — Long-Lived Secrets

> *Risk: credentials that live indefinitely, magnifying the impact of any leak.*

| gh-iga check | Severity | What it detects |
|---|---|---|
| Deploy key inventory | — | Every SSH deploy key on every scanned repo: title, repo, read/write, created, last used, added by. Deploy keys are long-lived per-repo credentials, typically with no expiry. |
| `deploy_keys_read_write` | Medium | Deploy keys with push access (see NHI5). |
| `deploy_keys_stale` | Low | Deploy keys unused for ≥ N days or never used (see NHI1). |
| Actions secrets inventory | — | Every GitHub Actions secret (repo + org level): name, scope, last updated. Names and timestamps only — values are never exposed by the API. |
| `secrets_not_rotated` | Medium | Actions secrets not updated in ≥ N days (default 365) — no rotation evidence on a stored long-lived credential. |

**Sample finding:**

```json
{
  "severity": "medium",
  "category": "deploy_keys_read_write",
  "title": "2 read-write deploy key(s) can push to repositories",
  "affected": ["web-app (ci-deploy)", "infra (terraform-bot)"]
}
```

> Note on PATs: fine-grained PAT inventory (`/orgs/{org}/personal-access-tokens`) is **not** covered — that endpoint requires a GitHub App token, which is incompatible with gh-iga's read-only, PAT-based, no-infrastructure design. Classic PATs are not centrally enumerable via the API at all.

### NHI10 — Human Use of NHI *(roadmap)*

Heuristic detection of shared machine/service accounts used interactively by humans. Deferred — GitHub has no formal service-account type, so this is naming/behaviour heuristic work rather than an authoritative API signal.

## Methodology notes

Detection of these risks in a GitHub environment reduces to three questions, independent of tooling:

1. **What identities exist — human and non-human?** Enumerate members, outside collaborators, and installed GitHub Apps, with effective permission per repo.
2. **Is the access still justified?** Cross-reference against activity signals (last commit/PR/review for humans; suspended state for apps) and team ownership.
3. **Is the access minimal?** Compare granted scope against need; flag admin where write suffices, and org-wide where a subset suffices.

`gh-iga` implements this methodology; the questions apply to any assessment approach, manual or automated.

## Try it

```bash
pip install gh-iga
export GITHUB_TOKEN=ghp_...   # read-only: repo, read:org, admin:org (for app inventory)
gh-iga scan --org your-org
```

Output: terminal summary, self-contained HTML report, Markdown, and JSON (SIEM-ready) — including the installed-app inventory. All local — nothing leaves your machine.
