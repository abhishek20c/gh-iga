# gh-iga ↔ OWASP Non-Human Identities Top 10 (2025) Mapping

This document maps **gh-iga's non-human-identity detections** to the [OWASP Non-Human Identities Top 10](https://owasp.org/www-project-non-human-identities-top-10/) risk categories, for GitHub organization environments.

> Scope note: gh-iga is also a general identity-governance scanner (it flags human-identity issues like admin sprawl, inactive privileged users, and over-permissioned repos). **Those human-identity checks are intentionally excluded from this mapping** — only genuine non-human identities are listed below.

`gh-iga` is read-only and MIT-licensed. Everything here is collected with **a single classic token** (`repo` + `read:org` + `admin:org`, run as an org owner) — no GitHub App, no infrastructure. All output stays local; no telemetry.

## What counts as a non-human identity here

GitHub Apps · SSH deploy keys · GitHub Actions secrets · the Actions `GITHUB_TOKEN` — each an autonomous actor or credential independent of any human user. **Webhooks** are also covered as a closely related **third-party integration surface** (NHI3): a webhook is an event subscription rather than an identity itself, but it represents the kind of third-party trust relationship the risk category concerns.

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

*Webhooks are included as a third-party integration surface, not as identities themselves — they're the trust relationships through which third parties receive org/repo events.*

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

A few things gh-iga doesn't do yet. None are dead ends — each is waiting on a specific blocker:

- **Fine-grained PAT inventory** — the `/orgs/{org}/personal-access-tokens` endpoint only works with a GitHub App token, not a plain PAT. I plan to add it behind an optional GitHub App auth mode, so the default "just paste a token" setup stays unchanged for everyone who doesn't need it.
- **OAuth apps & user-authorized apps** — there's currently no GitHub API to list these across an org (the old OAuth authorizations API was removed back in 2020). I'll add coverage if GitHub ships an endpoint for it, or through the App auth mode if that turns out to work.
- **Secret leak scanning** (NHI2) — gh-iga doesn't look for secrets hardcoded in code or commit history. That's a different problem, and tools like gitleaks and TruffleHog already handle it well. gh-iga lists the credentials an org *declares* (Actions secrets, deploy keys) rather than ones that leaked into a repo — so run it alongside a leak scanner if you want both covered.

## Try it

```bash
git clone https://github.com/abhishek20c/gh-iga.git
cd gh-iga && pip install -e .
export GITHUB_TOKEN=ghp_...   # one classic token: repo + read:org + admin:org
gh-iga scan --org your-org
```

Output: terminal summary, self-contained HTML report, Markdown, and JSON (SIEM-ready), including all NHI inventories above. All local — nothing leaves your machine.
