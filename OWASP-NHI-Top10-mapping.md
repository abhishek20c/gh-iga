# gh-iga ↔ OWASP Non-Human Identities Top 10 (2025) Mapping

This document maps `gh-iga` detection checks to the [OWASP Non-Human Identities Top 10](https://owasp.org/www-project-non-human-identities-top-10/) risk categories, for GitHub organization environments.

`gh-iga` is a read-only, MIT-licensed scanner. It requires only `repo` and `read:org` read scopes, writes all output locally, and sends no telemetry. While several of its checks target human identities, GitHub orgs are an environment where human and non-human identity risk are tightly coupled: outside collaborators, stale privileged accounts, and machine accounts (bot users, service accounts registered as org members) are detected by the same access-graph analysis.

## Coverage summary

| OWASP Risk | Risk Name | gh-iga Coverage | Status |
|---|---|---|---|
| **NHI1** | Improper Offboarding | Inactive privileged accounts, orphaned members | ✅ v0.1 (today) |
| **NHI5** | Overprivileged NHI | Admin sprawl, over-permissioned repos, privileged outside collaborators, redundant direct grants | ✅ v0.1 (today) |
| **NHI3** | Vulnerable Third-Party NHI | GitHub Apps & OAuth app inventory (incl. AI coding tools / MCP servers) | 🔜 Planned (v0.5) |
| **NHI7** | Long-Lived Secrets | Actions `GITHUB_TOKEN` least-privilege audit | 🔜 Planned (v0.3) |
| **NHI10** | Human Use of NHI | Machine-account detection heuristics | 🔜 Under consideration |

## Detailed mapping — available today (v0.1)

### NHI1 — Improper Offboarding

> *Risk: identities (human or machine) that retain access after they should have been deprovisioned.*

| gh-iga check | What it detects | Severity |
|---|---|---|
| `inactive_privileged` | Accounts with no recorded org activity for ≥ N days (default 90) that still hold write or admin access on one or more repos. Applies equally to human accounts and machine/bot accounts registered as members. | High |
| `orphaned_members` | Non-owner members on no team with no direct repo access — frequently a sign of incomplete offboarding or stale onboarding. | Medium |

**Sample finding (JSON output):**

```json
{
  "severity": "high",
  "category": "inactive_privileged",
  "title": "19 user(s) inactive 90+ days still hold write or admin access",
  "affected": ["ci-bot-legacy (inactive 412d, 7 repo(s))", "j-contractor (inactive 180d, 2 repo(s))"]
}
```

### NHI5 — Overprivileged NHI

> *Risk: identities granted broader access than their function requires.*

| gh-iga check | What it detects | Severity |
|---|---|---|
| `admin_sprawl` | Accounts holding admin on ≥ N active repos (default 5). | High |
| `privileged_outside_collaborators` | External (non-member) accounts with write or admin — these bypass org SSO and 2FA enforcement. Service accounts added as outside collaborators are a common NHI blind spot. | High |
| `over_permissioned_repos` | Repos with more than N unique admins (default 3) — inflated blast radius per compromised credential. | Medium |
| `direct_access_candidates` | Direct grants redundant with team-based access — shrinks the per-identity permission surface to audit. | Low |

**Sample finding:**

```json
{
  "severity": "high",
  "category": "privileged_outside_collaborators",
  "title": "8 outside collaborator(s) have write or admin access",
  "affected": ["deploy-svc (admin on infra-prod)", "vendor-sync-bot (write on api-gateway)"]
}
```

## Detailed mapping — roadmap

### NHI3 — Vulnerable Third-Party NHI *(planned, v0.5)*

Inventory and risk-rank all GitHub Apps and OAuth apps installed in the org — including AI coding tools (Copilot, Cursor, Claude Code, MCP servers), each of which is a third-party NHI with code access. Surfaces app permission scope, install date, and last use.

### NHI7 — Long-Lived Secrets *(planned, v0.3)*

Audit GitHub Actions workflow permissions for over-broad `GITHUB_TOKEN` grants (`permissions: write-all` and missing least-privilege blocks), the most common long-lived ambient credential in GitHub CI.

### NHI10 — Human Use of NHI *(under consideration)*

Heuristic detection of shared machine accounts used interactively by humans (commit/login pattern analysis).

## Methodology notes

Detection in a GitHub environment for these risks reduces to three questions, independent of tooling:

1. **Who/what has privileged access?** Enumerate members, outside collaborators, and installed apps with effective permission per repo (team-inherited + direct).
2. **Is the access still justified?** Cross-reference against activity signals (last commit/PR/review) and team ownership.
3. **Is the access minimal?** Compare granted scope against observed use; flag admin where write suffices, write where read suffices.

`gh-iga` implements this methodology; the questions apply to any assessment approach, manual or automated.

## Try it

```bash
pip install gh-iga
export GITHUB_TOKEN=ghp_...   # read-only: repo + read:org
gh-iga scan --org your-org
```

Output: terminal summary, self-contained HTML report, Markdown, and JSON (SIEM-ready). All local — nothing leaves your machine.
