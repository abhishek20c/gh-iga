# Publishing gh-iga to PyPI

This project is packaged with `pyproject.toml` and can be published to PyPI as the `gh-iga` package. After publishing, users can install it without cloning the repository:

```bash
pipx install gh-iga
# or
python -m pip install gh-iga
```

## One-time PyPI setup

1. Create a PyPI account at https://pypi.org.
2. Create the `gh-iga` project by doing the first publish manually, or configure trusted publishing before the first release if PyPI allows it for the pending project name.
3. In PyPI, configure trusted publishing for this repository:
   - Owner: `abhishek20c`
   - Repository: `gh-iga`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`
4. In GitHub, create an environment named `pypi` under repository settings. Add required reviewers if you want a manual approval gate before publishing.

Trusted publishing uses GitHub's OIDC token, so the workflow does not need a long-lived PyPI API token stored as a GitHub secret.

## Release checklist

1. Update the version in both places:
   - `pyproject.toml` under `[project].version`
   - `gh_iga/__init__.py` as `__version__`
2. Update `CHANGELOG.md`, `SECURITY.md`, and README examples when applicable.
3. Run formatting, lint, tests, and the package build locally:

   ```bash
   python -m black --check gh_iga tests
   python -m ruff check gh_iga tests
   python -m pytest -q
   python -m pip install --upgrade build twine
   python -m build
   python -m twine check dist/*
   ```

4. Tag the release, for example `v1.0.0`.
5. Create and publish a GitHub Release from that tag.
6. The `Publish to PyPI` workflow will build the package and upload it to PyPI.
7. Verify installation from a clean environment:

   ```bash
   pipx install gh-iga
   gh-iga --version
   ```

## Important notes

- PyPI versions are immutable. Once `1.0.0` is uploaded, that exact version cannot be overwritten. If something is wrong, publish `1.0.1`.
- Prefer `pipx install gh-iga` in user-facing docs because it installs the CLI in an isolated environment.
- Keep generated files out of Git. Built artifacts belong in `dist/` locally and are ignored by `.gitignore`.
