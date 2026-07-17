# Changelog

All notable changes to `gh-iga` are documented here.

The project follows [Semantic Versioning](https://semver.org/). Starting with
1.0.0, incompatible changes to stable CLI commands or documented report
semantics require a new major version.

## [1.0.0] - 2026-07-17

### Added

- A documented stable contract for the point-in-time, read-only scanner.
- A version 1.0 scope and limitations section covering authentication,
  visibility, activity data, unsupported identities, remediation, and API
  quota considerations.
- This changelog.

### Changed

- Reframed the roadmap around a stable scanner release. Continuous monitoring,
  webhook-driven updates, GitHub App authentication, and alerts remain future
  enhancements rather than 1.0 requirements.
- Declared the package Production/Stable.
- Migrated package licensing metadata to the PEP 639 SPDX form.
- Normalized the Python source and tests with Black and removed all Ruff
  violations.

### Fixed

- Removed the documentation claim that configuration-file support exists.

## [0.6.2] - 2026-07-17

### Added

- Explicit scan-completeness states: `complete`, `partial`, `skipped`, and
  `not_applicable`.
- Coverage details in terminal, HTML, Markdown, and JSON reports.
- Per-scope reasons when optional inventory endpoints cannot be inspected.

### Changed

- Expected permission-related gaps remain non-fatal and are reported.
- Authentication, rate-limit, and server failures propagate instead of being
  presented as empty inventory.

## [0.6.1] - 2026-07-09

### Changed

- Completed PyPI packaging and trusted-publishing documentation.
- Aligned runtime, package, and README version metadata.

## [0.6.0] - 2026-06-26

### Added

- GitHub organization and personal-repository scanning.
- Human access governance for members, teams, direct collaborators, outside
  collaborators, permissions, and activity.
- Non-human identity and integration inventories for installed GitHub Apps,
  deploy keys, Actions secrets, webhooks, and default `GITHUB_TOKEN`
  permissions.
- Governance findings mapped to relevant OWASP Non-Human Identities risks.
- Terminal, HTML, Markdown, and JSON reports.

[1.0.0]: https://github.com/abhishek20c/gh-iga/compare/v0.6.2...v1.0.0
[0.6.2]: https://github.com/abhishek20c/gh-iga/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/abhishek20c/gh-iga/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/abhishek20c/gh-iga/releases/tag/v0.6.0
