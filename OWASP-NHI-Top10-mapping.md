# gh-iga ↔ OWASP Non-Human Identities Top 10 (2025) Mapping

This document maps `gh-iga` detection checks to the [OWASP Non-Human Identities Top 10](https://owasp.org/www-project-non-human-identities-top-10/) risk categories, for GitHub organization environments.

`gh-iga` is a read-only, MIT-licensed scanner. It requires only read scopes (`repo`, `read:org`, and `admin:org` for the non-human-identity inventories), writes all output locally, and sends no telemetry. As of v0.2 it detects non-human identities directly: it inventories the GitHub Apps installed on an org and the fine-grained personal access tokens (PATs) with access to org resources, and flags the risky ones — alongside its original human-identity governance checks.

## Coverage summary

| OWASP Risk | Risk Name | gh-iga detection | Status |
|---|---|---|---|
| **NHI1** | Improper Offboarding | Inactive privileged accounts, orphaned members, suspended-but-installed apps | ✅ Shipped |
| **NHI3** | Vulnerable Third-Party NHI | GitHub App inventory; apps with org-wide repo access | ✅ Shipped (v0.2) |
| **NHI5** | Overprivileged NHI | Admin sprawl, over-permissioned repos, privileged outside collaborators; apps with admin/write permissions; org-wide PATs | ✅ Shipped |
| **NHI7** | Long-Lived Secrets | Fine-grained PAT inventory; PATs with no expiry | ✅ Shipped (v0.2) |
| **NHI10** | Human Use of NHI | Service/shared-account detection | 🔜 Roadmap |

The non-human-identity inventories (apps, PATs) are **org-scan only** — GitHub exposes no PAT-accessible API to enumerate apps or tokens on a personal account.

## Detailed mapping

### NHI1 — Improper Offboarding

> *Risk: identities (human or machine) that retain access after they should have been deprovisioned.*

| gh-iga check | Severity | What it detects |
|---|---|---|
| `inactive_privileged` | High | Accounts with no recorded org activity for ≥ N days (default 90) that still hold write/admin. |
| `orphaned_members` | Medium | Non-owner members on no team with no direct repo access — often incomplete on/offboarding. |
| `apps_suspended_installed` | Low | GitHub Apps that are suspended but still installed — a partially offboarded NHI that can be re-enabled. |

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
| `over_permissioned_repos` | Medium | Repos with more than N unique admins (default 3). |
| `pats_org_wide_access` | Medium | Fine-grained PATs scoped to all org repos rather than a subset. |
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
| Fine-grained PAT inventory | — | Lists every fine-grained PAT with access to org resources: owner, repo scope, expiry, last used. |
| `pats_no_expiry` | High | PATs with org access and **no expiration date** — a leaked or forgotten token stays valid forever. |

**Sample finding:**

```json
{
  "severity": "high",
  "category": "pats_no_expiry",
  "title": "4 fine-grained PAT(s) have no expiration date",
  "affected": ["alice (ci-runner)", "deploy-svc (prod-deploy)"]
}
```

> Fine-grained PAT inventory requires the org to have enabled the fine-grained PAT approval policy. Classic PATs are not centrally enumerable via the GitHub API.

### NHI10 — Human Use of NHI *(roadmap)*

Heuristic detection of shared machine/service accounts used interactively by humans. Deferred — GitHub has no formal service-account type, so this is naming/behaviour heuristic work rather than an authoritative API signal.

## Methodology notes

Detection of these risks in a GitHub environment reduces to three questions, independent of tooling:

1. **What identities exist — human and non-human?** Enumerate members, outside collaborators, installed GitHub Apps, and org-scoped PATs, with effective permission per repo.
2. **Is the access still justified?** Cross-reference against activity signals (last commit/PR/review for humans; last-used and suspended state for tokens/apps) and team ownership.
3. **Is the access minimal and time-bound?** Compare granted scope against need; flag admin where write suffices, org-wide where a subset suffices, and credentials with no expiry.

`gh-iga` implements this methodology; the questions apply to any assessment approach, manual or automated.

## Try it

```bash
pip install gh-iga
export GITHUB_TOKEN=ghp_...   # read-only: repo, read:org, admin:org (for app/PAT inventory)
gh-iga scan --org your-org
```

Output: terminal summary, self-contained HTML report, Markdown, and JSON (SIEM-ready) — including the installed-app and PAT inventories. All local — nothing leaves your machine.
