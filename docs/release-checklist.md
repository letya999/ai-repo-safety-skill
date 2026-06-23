# Release checklist for the maintainer

This document is the manual portion of a release. The automated
`ai-repo-safety verify-release` command covers most pre-flight
checks; this checklist covers the GitHub-side and registry-side
config that lives outside the source tree.

A release is ready to publish when **all** of the following are
true.

## 1. Local pre-flight

```bash
# From the project root, on the `dev` branch:
git status                           # clean
git fetch origin                     # origin/dev and origin/main in sync
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest tests/ -q
ruff check .
ai-repo-safety git-integrity --target .
rm -rf dist && uv build --no-sources
uvx twine check dist/*
python scripts/check-package-artifacts.py
bash scripts/smoke-wheel.sh
ai-repo-safety verify-release --version X.Y.Z
```

All `verify-release` checks should report `[OK]`. The
shipped wheel must install cleanly into a fresh `python -m venv`
and `ai-repo-safety init --python yes --github no` must produce
the expected file set without raising.

If `git-integrity` reports warnings, review them before tagging.
Warnings do not automatically prove compromise, but they are a
signal to inspect branch divergence, reflog rewrite events, blame,
and signature state before trusting the release history.

## 2. CI green

Open the GitHub Actions tab and confirm the following runs are
green on the head commit of `dev`:

- `ci / test (py3.12, 3.13)`
- `ci / package-smoke`
- `ci / npm-smoke`
- `dependency-review` (on every PR; not on push)
- `security` (gitleaks + trufflehog)
- `sast` (bandit + ruff)
- `supply-chain` (osv-scanner + pip-audit)
- `scorecard` (weekly; can be skipped if last green run is recent)

If any of the release-blocking workflows is red, fix the
underlying issue and re-run. Do not push a release tag while a
release-blocking workflow is failing on `dev`.

## 3. PyPI Trusted Publisher configuration

Navigate to `https://pypi.org/manage/project/ai-repo-safety/settings/publishing/`
and confirm the Trusted Publisher entry exists with these
values:

- Owner / organization: `letya999`
- Repository: `ai-repo-safety-skill`
- Workflow filename: `publish-pypi.yml`
- Environment name: `pypi`
- Allowed actions: `publish` (and `stage` if using staged publishing)

If any of those values is missing or stale, add or correct the
entry before tagging. PyPI does not validate the configuration at
save time, so a typo will only surface as a publish failure on
the next tag.

After configuration: optionally enable the **maximum security**
posture: Settings → Publishing access → "Require two-factor
authentication and disallow tokens". Trusted Publishing keeps
working under that setting because it uses OIDC, not long-lived
tokens.

## 4. npm publish configuration

Preferred setup: navigate to
`https://www.npmjs.com/package/ai-repo-safety/settings`
(you must be an owner or maintainer) and confirm the Trusted
Publisher entry exists with these values:

- Organization or user: `letya999`
- Repository: `ai-repo-safety-skill`
- Workflow filename: `publish-npm.yml`
- Environment name: `npm`
- Allowed actions: `npm publish` (and `npm stage publish` if using
  staged publishing)

Fallback setup: if Trusted Publishing is not configured yet,
confirm the GitHub Actions secret `NPM_TOKEN` exists and still has
publish rights for the `ai-repo-safety` package. The repository
currently supports both paths and will use `NPM_TOKEN` as the
compatibility fallback.

## 5. GitHub branch protection (owner action)

Branch protection is the social layer that complements SHA-pinning
and CODEOWNERS. The recommended setup for `dev` and `main`:

- Require pull-request reviews before merge: 1 (or 2 for
  security-sensitive files)
- Require review from Code Owners: yes (this uses
  `.github/CODEOWNERS` which already gates `.github/workflows/`)
- Require status checks to pass before merge: yes — at minimum
  `ci / test (py3.12)`, `ci / package-smoke`, `ci / npm-smoke`,
  `dependency-review`
- Require signed commits: optional but recommended
- Require linear history: optional
- Include administrators: yes (admin PRs should still require a
  review)
- Allow force pushes: no
- Allow deletions: no

Apply via `https://github.com/letya999/ai-repo-safety-skill/settings/branches`
or with `gh api -X PUT repos/letya999/ai-repo-safety-skill/branches/dev/protection -f ...`.

## 6. Tag and push

```bash
git checkout dev
git pull --rebase origin dev
git tag -s vX.Y.Z -m "ai-repo-safety X.Y.Z"
git push origin vX.Y.Z
```

The `-s` flag signs the tag with your GPG or SSH key, allowing
downstream consumers to verify provenance. If you do not have a
signing key configured, drop the `-s`.

The push triggers `publish-pypi.yml` and `publish-npm.yml`. Both
have a smoke gate (`build-and-smoke` and `pack-smoke`
respectively) that runs first; the publish step waits for those
to complete. If the smoke gate fails, the publish does not run.

## 7. Verify the publish

```bash
# Watch the workflow runs:
gh run list --repo letya999/ai-repo-safety-skill --workflow=publish-pypi --limit 1 --json status,conclusion
gh run list --repo letya999/ai-repo-safety-skill --workflow=publish-npm --limit 1 --json status,conclusion

# Confirm the new version is on PyPI:
pip index versions ai-repo-safety 2>/dev/null || curl -s https://pypi.org/pypi/ai-repo-safety/json | python -c "import json,sys; print(json.load(sys.stdin)['info']['version'])"

# Confirm the new version is on npm:
npm view ai-repo-safety@X.Y.Z version
```

## 8. GitHub Release

```bash
gh release create vX.Y.Z \
    --repo letya999/ai-repo-safety-skill \
    --title "ai-repo-safety vX.Y.Z" \
    --notes-file CHANGELOG.md \
    --target dev
```

This creates the human-readable release page that GitHub users
will see. PyPI and npm both generate their own changelog-style
pages from the package metadata; the GitHub release complements
those with a maintainer-written summary.

## 9. Optional: yank the previous broken release

The 0.1.3 wheel on PyPI is broken (`init` fails with
`FileNotFoundError` because the wheel was missing the asset
templates). The 0.1.4 (or whichever emergency-patch version you
publish) supersedes it. To keep `pip install ai-repo-safety`
clean for new users, you can yank 0.1.3 from PyPI:

```bash
# 0.1.3 cannot be deleted from PyPI, only yanked.
# yanking hides it from `pip install` but keeps the version
# available for already-pinned environments.
```

There is no equivalent of "yank" on the npm registry. The
maintainer can `npm deprecate ai-repo-safety@0.1.3` to print a
warning when users install that version, but the version remains
installable.

## 10. Post-release verification

After the tag push and `gh release create` complete, run the
`ai-repo-safety` smoke once more against the published release:

```bash
python -m venv /tmp/ars-after-release
/tmp/ars-after-release/bin/pip install --upgrade ai-repo-safety==X.Y.Z
/tmp/ars-after-release/bin/ai-repo-safety --version
/tmp/ars-after-release/bin/ai-repo-safety init --target /tmp/ars-after-target --python yes --github no
test -f /tmp/ars-after-target/AGENTS.md
test -f /tmp/ars-after-target/SECURITY.md
test -f /tmp/ars-after-target/.repo-safety/opengrep/python-dangerous-code.yml
```

This is the same smoke the CI `package-smoke` job runs, but
against the actual published artifact rather than the locally
built one. Catches registry-side issues (filename corruption on
upload, mismatched metadata) that the CI gate cannot see.

---

If any of the above fails, the safest response is to yank the
new release and investigate before publishing a fix. A broken
release of a security tool is worse than a delayed release.
