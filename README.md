# gh-iga™

**The open-source identity governance scanner for GitHub.**  
Know who has access to what — in 60 seconds.

[![PyPI version](https://img.shields.io/pypi/v/gh-iga.svg)](https://pypi.org/project/gh-iga/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![GitHub Stars](https://img.shields.io/github/stars/abhishek20c/gh-iga.svg)](https://github.com/abhishek20c/gh-iga/stargazers)

---

Most GitHub orgs have no idea who can actually push to production.

`gh-iga` gives you a complete picture of your GitHub org's access posture in a single command — members, teams, repos, permissions, and the risks hiding inside all of it. No dashboards to set up. No agents to deploy. Just run it and get a report you can share with your team or hand to an auditor.

```
$ gh-iga scan --org myorg

  gh-iga — Identity Governance Scanner for GitHub
  ─────────────────────────────────────────────────
  Org:      myorg
  Members:  84       Teams:  12       Repos: 203

  RISK FINDINGS
  ✗  12 users have admin access to 5+ repos (admin sprawl)
  ✗   8 outside collaborators have write or admin access
  ✗  19 users inactive 90+ days still hold write/admin
  ✗   6 repos have 4+ admins (over-permissioned)
  ⚠   31 users on no team and no direct repo access (orphaned)
  ⚠   14 users with direct repo access could move to teams

  Report written → gh-iga-report-myorg-20260509.html
  JSON output   → gh-iga-report-myorg-20260509.json
```

---

## Why gh-iga™?

GitHub is where your code — and your blast radius — lives. But GitHub's native UI makes it nearly impossible to answer the questions that actually matter for security and compliance:

- Which engineers can push to every repo in the org?
- Who joined 18 months ago and still has admin on 30 repos?
- Which outside contractors still have write access?
- Are any repos owned by no team — just a handful of individual admins?

`gh-iga` answers all of these, automatically, every time you run it.

---

## Install

### Prerequisites

- **Python 3.9+** — [python.org/downloads](https://www.python.org/downloads/)
  - Windows: check **"Add Python to PATH"** during install
- **Git** — [git-scm.com](https://git-scm.com)

### From PyPI *(once published)*

```bash
pip install gh-iga
```

### From source *(now)*

```bash
git clone https://github.com/abhishek20c/gh-iga.git
cd gh-iga
pip install -e .
```

> If `pip` isn't recognised on Windows, use `py -m pip install -e .` instead.

Verify it worked:

```bash
gh-iga --version
# gh-iga, version 0.1.0
```

---

## Quickstart

### 1. Create a GitHub token

Go to [github.com/settings/tokens → New classic token](https://github.com/settings/tokens) and grant these scopes:

| Scope | Required for |
|-------|-------------|
| `repo` | Reading repo collaborators and permissions |
| `read:org` | Reading org members and teams *(org scan only)* |

> **No write permissions are ever needed or used.** `gh-iga` is read-only by design.

### 2. Set your token

| Shell | Command |
|-------|---------|
| Mac / Linux | `export GITHUB_TOKEN=ghp_your_token_here` |
| Windows PowerShell | `$env:GITHUB_TOKEN = "ghp_your_token_here"` |
| Windows CMD | `set GITHUB_TOKEN=ghp_your_token_here` |

### 3. Scan

**No org? Scan your personal repos:**

```bash
gh-iga scan-user
```

**Have a GitHub org:**

```bash
gh-iga scan --org your-org-name
```

That's it. A self-contained HTML report, a Markdown report, and a JSON file land in your current directory. Open the `.html` file in any browser.

---

## What it scans

| Area | Detail |
|------|--------|
| **Org members** | All members with role (owner / member) |
| **Outside collaborators** | Every external user and their repo-level permissions |
| **Repos** | Per-repo access list with permission levels (admin / maintain / write / triage / read) |
| **Teams** | Membership, team-level repo permissions, and nesting |
| **Activity** | Last commit/PR activity per user — proxy for "is this person still active?" |

---

## What it flags

### High severity
- **Admin sprawl** — users with admin access to more than N repos (default: 5)
- **Inactive admins/writers** — users with no activity in 90+ days who still hold write or admin access
- **Privileged outside collaborators** — any external user with write or admin on any repo

### Medium severity
- **Over-permissioned repos** — repos with more than N admins (default: 3)
- **Orphaned users** — org members on no team and with no direct repo access

### Hygiene
- **Direct access candidates** — users with direct repo access who could be governed through a team instead

All thresholds are configurable via flags or a config file.

---

## Output formats

| Format | Flag | Use case |
|--------|------|----------|
| Terminal summary | (default) | Quick review in CI or your shell |
| HTML report | `--html` (default on) | Share with your team or auditors |
| Markdown report | `--markdown` | Drop into a GitHub issue or Confluence |
| JSON | `--json` (default on) | Pipe into SIEM, Splunk, your own scripts |

All output is written locally. Nothing is sent anywhere.

---

## Options

```
Usage: gh-iga scan [OPTIONS]

Options:
  --org TEXT              GitHub org to scan  [required]
  --token TEXT            GitHub token (or set GITHUB_TOKEN env var)
  --output-dir TEXT       Directory to write reports (default: current dir)
  --format [html|md|json|all]
                          Output format (default: all)
  --inactive-days INT     Days of inactivity to flag (default: 90)
  --admin-sprawl-threshold INT
                          Repos with admin access to flag user (default: 5)
  --max-admins-per-repo INT
                          Admins per repo before flagging (default: 3)
  --no-html               Disable HTML report
  --no-json               Disable JSON output
  --help                  Show this message and exit.
```

---

## CI / automation

Run `gh-iga` on a schedule in GitHub Actions:

```yaml
name: Weekly access review

on:
  schedule:
    - cron: '0 9 * * 1'   # every Monday at 9am

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pipx install gh-iga
      - run: gh-iga scan --org ${{ github.repository_owner }}
        env:
          GITHUB_TOKEN: ${{ secrets.GH_IGA_TOKEN }}
      - uses: actions/upload-artifact@v4
        with:
          name: access-report
          path: gh-iga-report-*.html
```

---

## Roadmap

| Version | What's coming |
|---------|--------------|
| **v0.1** | GitHub org scan + HTML / Markdown / JSON reports ← *you are here* |
| **v0.2** | GitHub App auth, scheduled scans, delta reports ("what changed since last run") |
| **v0.3** | GitHub Actions workflow permissions audit (least-privilege `GITHUB_TOKEN` checks) |
| **v0.4** | Branch protection drift detection (who disabled required reviews, when) |
| **v0.5** | GitHub Apps & OAuth apps governance — including AI coding tools (Copilot, Cursor, Claude Code, MCP servers) |
| **v1.0** | Continuous monitoring mode, webhook-driven updates, Slack/email alerts |

v0.5 is where this gets interesting for the AI-coding era: every Copilot, Cursor, or MCP server your team installs is a GitHub App with access to your code. `gh-iga` will surface all of them.

---

## Comparison

| | gh-iga | GitHub native UI | Gitguardian / Nightfall | Terraform / Policy-as-code |
|---|:---:|:---:|:---:|:---:|
| Org access overview | ✅ | ⚠ Partial | ❌ | ❌ |
| Inactive user flagging | ✅ | ❌ | ❌ | ❌ |
| Admin sprawl detection | ✅ | ❌ | ❌ | ❌ |
| Outside collaborator audit | ✅ | ⚠ Manual | ❌ | ❌ |
| Shareable HTML report | ✅ | ❌ | ✅ (paid) | ❌ |
| JSON / pipeline output | ✅ | ❌ | ✅ (paid) | ✅ |
| Free & self-hosted | ✅ | ✅ | ❌ | ✅ |
| No write token needed | ✅ | — | ✅ | ✅ |

---

## Security & privacy

- `gh-iga` requires **read-only** scopes. It cannot modify your org, repos, or permissions.
- All data stays on your machine. No telemetry, no callbacks, no external services.
- The token is never written to disk or included in any report output.
- If you find a security issue in `gh-iga` itself, please report it privately via [GitHub Security Advisories](https://github.com/abhishek20c/gh-iga/security) rather than a public issue.

---

## Who's using gh-iga?

See [ADOPTERS.md](ADOPTERS.md) for organizations and individuals running gh-iga in the wild.

Using it yourself? [Open a PR to add yourself](ADOPTERS.md) — or drop a note in [Discussions](https://github.com/abhishek20c/gh-iga/discussions).

---

## Early feedback

gh-iga is at v0.1 and actively shaped by real-world use cases.

If you've run it against your org — even just to kick the tyres — I'd love to hear:
- What access problems did it surface?
- What would make the report more useful to your team or auditors?
- What's missing from the roadmap?

👉 **[Start a discussion](https://github.com/abhishek20c/gh-iga/discussions/new?category=general)** or open an issue. Every piece of feedback directly influences the roadmap.

---

## License

MIT — see [LICENSE](LICENSE).

---

<p align="center">
  Built to make GitHub access reviews something you actually do.<br>
  If this saves you time, a ⭐ goes a long way.
</p>
