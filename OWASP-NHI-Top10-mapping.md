# gh-iga ↔ OWASP Non-Human Identities Top 10 (2025) Mapping

This document maps **gh-iga's non-human-identity detections** to the [OWASP Non-Human Identities Top 10](https://owasp.org/www-project-non-human-identities-top-10/) risk categories, for GitHub organization environments.

> Scope note: gh-iga is also a general identity-governance scanner (it flags human-identity issues like admin sprawl, inactive privileged users, and over-permissioned repos). **Those human-identity checks are intentionally excluded from this mapping** — only genuine non-human identities are listed below.

`gh-iga` is read-only and MIT-licensed. Everything here is collected with **a single classic token** (`repo` + `read:org` + `admin:org`, run as an org owner) — no GitHub App, no infrastructure. All output stays local; no telemetry.

## What counts as a non-human identity here

GitHub Apps · SSH deploy keys · GitHub Actions secrets · webhooks (third-party trust relationships) · the Actions `GITHUB_TOKEN`. Each is an autonomous actor or credential independent of any human user.

## Coverage summary

| OWASP Risk | Risk Name | gh-iga NHI detection | Status |
|---|---|---|---|
| **NHI1** | Improper Offboarding | Suspended-but-installed apps; stale/unused deploy keys | ✅ Shipped |
| **NHI3** | Vulnerable Third-Party NHI | GitHub App inventory + org-wide apps; webhooks (no secret, insecure transport) | ✅ Shipped |
| **NHI5** | Overprivileged NHI | Apps with admin/write perms; read-write deploy keys; read-write `GITHUB_TOKEN` default; Actions PR-approval | ✅ Shipped |
| **NHI7** | Long-Lived Secrets | Deploy key inventory; Actions secrets inventory (unrotated) | ✅ Shipped |
| **NHI10** | Human Use of NHI | Service/shared-account detection | 🔜 Roadmap |

The GitHub App inventory is **org-scan only** (no PAT-accessible API for personal-account apps). Deploy keys, Actions secrets, webhooks, and workflow-token checks run on both org and personal scans (per-repo, where the token has admin on the repo).

## Detailed mapping

### NHI1 — Improper Offboarding
> *Risk: machine identities that retain access after they should have been deprovisioned.*

| gh-iga check | Severity | What it detects |
|---|---|---|
| `apps_suspended_installed` | Low | GitHub Apps suspended but still installed — a partially offboarded NHI that can be re-enabled. |
| `deploy_keys_stale` | Low | Deploy keys unused for ≥ N days (or never) — forgotten standing credentials. |

### NHI3 — Vulnerable Third-Party NHI
> *Risk: third-party machine identities (apps, integrations) with excessive or unmonitored access.*

| gh-iga check | Severity | What it detects |
|---|---|---|
| GitHub App inventory | — | Every installed GitHub App with its permissions, repo scope, and status. Each is a third-party NHI with autonomous access. |
| `apps_org_wide_access` | Medium | Apps installed with "all repositories" access — org-wide blast radius. |
| `webhooks_no_secret` | Medium | Active webhooks with no signing secret — payloads can't be verified as from GitHub. |
| `webhooks_insecure_transport` | Medium | Webhooks over http:// or with SSL verification disabled. |

### NHI5 — Overprivileged NHI
> *Risk: identities granted broader access than their function requires.*

| gh-iga check | Severity | What it detects |
|---|---|---|
| `apps_admin_permissions` | High | Installed apps holding admin-level permissions. |
| `apps_write_permissions` | Medium | Installed apps holding write-level permissions. |
| `deploy_keys_read_write` | Medium | Deploy keys with push access. |
| `workflow_token_write_default` | Medium | The Actions `GITHUB_TOKEN` defaults to read-write (org default or repo override) — the most-used CI credential, overprivileged. |
| `workflow_can_approve_prs` | Low | Actions allowed to approve pull requests — bypasses required human review. |

### NHI7 — Long-Lived Secrets
> *Risk: credentials that live indefinitely, magnifying the impact of any leak.*

| gh-iga check | Severity | What it detects |
|---|---|---|
| Deploy key inventory | — | Every SSH deploy key: repo, read/write, created, last used, added by. Long-lived, usually no expiry. |
| Actions secrets inventory | — | Every Actions secret (repo + org): name, scope, last updated. Names and timestamps only — values are never exposed by the API. |
| `secrets_not_rotated` | Medium | Actions secrets not updated in ≥ N days (default 365) — no rotation evidence. |

### NHI10 — Human Use of NHI *(roadmap)*
Heuristic detection of shared machine/service accounts used interactively by humans. Deferred — GitHub has no formal service-account type, so this is heuristic rather than an authoritative API signal.

## Not covered yet — status and plan

These are on the radar; each is gated by a specific constraint rather than abandoned:

- **Fine-grained PAT inventory** — the `/orgs/{org}/personal-access-tokens` endpoint requires a GitHub App token, not a PAT. **Planned** for an optional GitHub App auth tier (roadmap), which adds it without compromising the default single-token, no-infrastructure mode.
- **OAuth apps & user-authorized apps** — GitHub currently exposes no org-wide API to enumerate these (the OAuth authorizations API was retired in 2020). **Will add** as soon as a suitable endpoint exists, or via the GitHub App auth tier where feasible — tracking the gap.
- **Secret leak scanning** (NHI2) — detecting secrets committed *in code* is a complementary tool class (e.g. gitleaks, TruffleHog). gh-iga focuses on inventorying *declared* non-human credentials; it pairs cleanly with a leak scanner for full NHI2 + NHI7 coverage, and integration is open for discussion.

## Try it

```bash
git clone https://github.com/abhishek20c/gh-iga.git
cd gh-iga && pip install -e .
export GITHUB_TOKEN=ghp_...   # one classic token: repo + read:org + admin:org
gh-iga scan --org your-org
```

Output: terminal summary, self-contained HTML report, Markdown, and JSON (SIEM-ready), including all NHI inventories above. All local — nothing leaves your machine.
