# Security Policy

## Supported Versions

Security fixes are applied to the latest stable release.

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ |
| < 1.0   | ❌ |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you find a security issue in `gh-iga` — for example, a way to extract
token values from report output, a path traversal in report writing, or a
dependency with a known CVE — please report it privately:

👉 [Open a GitHub Security Advisory](https://github.com/abhishek20c/gh-iga/security/advisories/new)

### What to include

- A description of the issue and its potential impact
- Steps to reproduce or a proof-of-concept
- The version of `gh-iga` you were running
- Your OS and Python version

### What to expect

- **Acknowledgement** within 48 hours
- **Status update** within 7 days (accepted, declined, or needs more info)
- **Credit** in the release notes if the issue is confirmed and fixed

## Security design notes

A few things worth knowing about how `gh-iga` handles data:

- **Read-only behavior** — the tool only ever calls read endpoints. Full
  inventory may require broad classic PAT scopes such as `repo` and
  `admin:org`, but `gh-iga` does not call write endpoints and cannot modify
  your org, repos, or permissions.
- **Token never persisted** — your GitHub token is only held in memory during
  the scan. It is never written to disk or included in any report output.
- **No outbound calls** — reports are written locally. No telemetry, no
  callbacks, no third-party services.
- **Dependencies** — we use a minimal set of well-maintained dependencies
  (`requests`, `click`, `rich`, `jinja2`). If you find a CVE in one of them,
  please report it upstream and open an issue here so we can update our pin.
