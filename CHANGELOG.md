# Changelog

All notable changes to this project will be documented in this
file. Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- Wheel and sdist artifacts now include every asset template the
  runtime CLI requires. The previous `0.1.3` release failed
  `ai-repo-safety init` with `FileNotFoundError` for `AGENTS.md`
  because the project `.gitignore` did not root-anchor generated
  filenames; that exclusion no longer matches the same files
  inside `src/ai_repo_safety/assets/`. (D0)
- `__version__` is now derived from installed package metadata via
  `importlib.metadata.version`, so `ai-repo-safety --version`
  matches `pip freeze` instead of reporting a stale literal.
  (D1)
- The npm wrapper (`bin/cli.js`) no longer delegates to
  `uvx ai-repo-safety@latest`. It now pins to
  `ai-repo-safety==<npm-package-version>` so the npm and PyPI
  releases move in lockstep. (D2)
- `setup` is plan-only by default and refuses to install system
  tools, run git hooks, or call any GitHub API unless the caller
  passes `--apply --yes` and the matching opt-in flag. (D4)
- `test_setup_project` is now deterministic and CI-friendly: it
  runs the default plan mode and does not require network,
  installed scanners, or `gh` auth. (D3)
- `import ai_repo_safety.util` no longer mutates `os.environ['PATH']`
  as a side effect. The CLI now calls the explicit
  `prepare_cli_environment()` once from `main()`. (D18)
- The fast scanner no longer self-reports on `.env.example` files
  or PEM-style placeholder strings inside `templates/`. A new
  `secret_placeholder` finding type and an inline
  `pragma: allowlist secret` directive make the contract
  explicit. (D8)
- `ai-repo-safety github-guard check-text` rejects paths that
  escape the target root. (D12)
- `ai-repo-safety install-hooks` refuses to overwrite an existing
  unmanaged pre-push hook; pass `--chain` to keep it and append
  a managed block, or `--overwrite` to replace it. (D9)
- The scanner uses `sys.executable` rather than the bare `python`
  alias for local helper script invocations. (D17)
- `trufflehog --since-commit` resolution handles short history and
  missing upstream via a robust `merge-base` / `rev-list` helper.
  (D10)
- The scanner has an `offline` mode that skips `pip-audit` with
  a clear `skipped: network_required` status rather than failing
  the run.

### Added
- `ai-repo-safety verify-release --version X.Y.Z` performs a
  set of pre-release checks: version consistency, workflow SHA
  pinning, no `NODE_AUTH_TOKEN` in the publish step, smoke
  scripts present, npm wrapper pinned, and an optional
  `uv build + twine check + artifact manifest` round-trip.
- `src/ai_repo_safety/results.py` defines `Status`, `Severity`,
  `FindingCategory`, `ToolRun`, `Finding`, and `ScanReport`
  dataclasses with a documented exit code contract:
  `0` ok, `1` findings, `2` tool error, `3` partial,
  `4` policy violation, `5` internal error.
- `scripts/smoke-wheel.sh` and
  `scripts/check-package-artifacts.py` provide an installed-wheel
  smoke that catches the `0.1.3` regression class before
  publication.
- `tests/test_packaging.py`,
  `tests/test_fast_scan.py`,
  `tests/test_util_path.py`,
  `tests/test_results.py`,
  `tests/test_github_guard.py`,
  `tests/test_verify_release.py`,
  `tests/test_hooks.py` — 50 test cases in total, all
  deterministic and network-free.
- `docs/opencode.md` describes the recommended OpenCode flow
  for projects that have run `ai-repo-safety init`.
- A root `AGENTS.md` and `SECURITY.md` so this repository
  dogfoods its own safety guardrails.

### CI / release
- Every `uses:` ref in `.github/workflows/*.yml` is pinned to
  a full 40-character commit SHA with an inline human-readable
  version comment. (D5)
- `publish-npm.yml` is rewritten around npm Trusted Publishing
  (OIDC); the long-lived `NPM_TOKEN` path is documented as
  legacy and the workflow explicitly empties `NODE_AUTH_TOKEN`
  so the OIDC token takes effect. (D6)
- `publish-pypi.yml` retains the existing PyPI Trusted
  Publishing flow but adds an installed-wheel smoke gate and
  an artifact upload between build and publish.
- New `ci.yml` runs pytest on Python 3.12 and 3.13, ruff, and
  the package / npm smoke scripts on every push and pull
  request. (D14, D17)
- New `dependency-review.yml` runs `actions/dependency-review-action`
  on every pull request with `fail-on-severity: high`.
- `scorecard.yml` now triggers on both `dev` and `main`
  pushes. (D19)
- The hardened workflow files are also updated inside
  `src/ai_repo_safety/assets/workflows/` so the templates this
  project copies to target repositories carry the same
  SHA-pinned convention. (D5)

## [0.1.3] - 2026-06-15

### Note

The `0.1.3` wheel published on PyPI and npm is broken: a fresh
install followed by `ai-repo-safety init --python yes --github no`
raises `FileNotFoundError` for `AGENTS.md` because the wheel
distribution does not include the asset templates. The fix is
in the next release; the next version is `0.1.4` (emergency
patch). Maintainers may want to yank `0.1.3` with reason
`Broken package assets; ai-repo-safety init fails after install`.

### Added
- Initial public release. CLI: doctor, install-missing, setup,
  init, install-hooks, scan, prepush, threat-model, incident,
  github-guard. Asset templates for universal, Python, and
  GitHub profiles. Opengrep rulepack with six rules.
