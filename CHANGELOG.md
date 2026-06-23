# Changelog

All notable changes to this project will be documented in this
file. Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.6] - 2026-06-23

### Fixed
- Restored the working npm publish path by wiring
  `NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}` back into
  `publish-npm.yml`. `0.1.5` reached PyPI successfully, but npm
  publish failed because the repository's Trusted Publisher path
  was not yet active in practice.
- `ai-repo-safety verify-release` now checks that the npm publish
  workflow has a usable auth path instead of incorrectly
  forbidding the token-based fallback that this repository still
  relies on.
- Release documentation now reflects the real support model:
  PyPI is OIDC-first; npm prefers OIDC but still supports
  `NPM_TOKEN` fallback until the Trusted Publisher path is fully
  proven.

## [0.1.5] - 2026-06-23

### Added
- Minimal project-local agent hooks for Codex, Claude Code,
  OpenCode, and Antigravity. `ai-repo-safety install-agent-hooks`
  now generates repo-local runtime configs plus a shared
  cross-platform `agent_hook_runner.py` for pre-tool security
  gates on Windows, WSL, macOS, and Linux.
- MCP hardening for GitHub and GitLab usage:
  `scan_mcp_config.py` now checks for plaintext credentials,
  over-privileged scopes, unpinned `npx` / `uvx` launchers,
  mutable `docker:latest`, expiry / rotation gaps, and missing
  audit hints in sensitive configs.
- `ai-repo-safety git-integrity --target .`, a lightweight local
  audit for suspicious history rewriting, attribution anomalies,
  and unsigned-history hints before release.
- `gitlab-guard` parity with `github-guard`, plus packaged GitLab
  templates and tests so GitLab context reads and CI templates
  are covered by the same safety posture.
- `.github/CODEOWNERS` gates changes to workflows, packaged
  assets, release-policy files, and the default catch-all. This
  complements SHA-pinned GitHub Actions with a review barrier.
- `package.json` `scripts.pack:check` and `scripts.smoke:bin`
  for local npm verification.
- `docs/release-checklist.md` now documents the maintainer's
  end-to-end release procedure, including local pre-flight, CI
  green, Trusted Publisher setup, signed tags, and
  post-publish verification.
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
  `tests/test_hooks.py` and the new hook / guard parity suites
  keep the release path deterministic and network-free.
- `docs/opencode.md` describes the recommended OpenCode flow
  for projects that have run `ai-repo-safety init`.
- A root `AGENTS.md` and `SECURITY.md` so this repository
  dogfoods its own safety guardrails.

### Changed
- The default sensitive-command preflight is now a compact
  security profile: `gitleaks` and `trufflehog` are mandatory,
  `opengrep` runs when a rulepack exists, and `bandit` runs when
  the repo looks like Python. This keeps the hook surface small
  while still gating the highest-risk operations.
- Project-local MCP hook coverage is now explicit for
  `mcp__github__.*` and `mcp__gitlab__.*` instead of a single
  ambiguous matcher, and generated configs now include explicit
  Windows command fields where runtimes support them.
- `publish-pypi.yml` now uses `uv build --no-sources` per the
  uv documentation recommendation for release builds, so the
  wheel builds identically under `pypa/build` and any other
  backend.
- `publish-npm.yml` now disables
  `actions/setup-node package-manager-cache` in release builds
  per the npm documentation recommendation that release builds
  never use the package-manager cache.
- `verify-release` now performs 10 checks instead of 8, adding
  `package.json declares node and npm engines floors` and
  `.github/CODEOWNERS gates .github/workflows/ changes`. The
  exit code contract is unchanged.
- `renovate.json` now groups GitHub Actions updates into a
  single PR (`groupName: "github-actions"`) and explicitly
  enables `pinDigests: true` for action dependencies. The
  `automerge: false` policy is preserved so the maintainer
  reviews dependency bumps manually.

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
- The generated hook preflight and the repo's own `scan` command
  now exclude `src/ai_repo_safety/assets/rules/opengrep/` from
  OpenGrep target scanning. This prevents the tool from
  self-reporting on its own rule definitions during dogfooding.
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
- The `ai-repo-safety sbom` command previously invoked
  `cyclonedx-py project`, which is not a real subcommand of
  `cyclonedx-bom` v7.3.0 (March 2026). The command now dispatches
  to the documented subcommands `environment`, `requirements`,
  `pipenv`, or `poetry`. The default scope changed from
  `project` to `environment`. The PyPI package name is
  `cyclonedx-bom`; the installed binary keeps the historical
  name `cyclonedx-py`.
- `index.js` is now a documented no-op proxy (`module.exports =
  {}`) that satisfies `package.json.main` for `npm ls` and
  IDEs without misleading consumers into believing there is a
  Node API.
- `package.json` now declares the runtime floors that the
  June 2026 npm Trusted Publishing reference requires:
  `engines.node: ">=18"` and `engines.npm: ">=11.5.1"`. The
  publish workflow continues to use Node 22.14.0 explicitly.
- The asset template `assets/scripts/github_read_guard.py`
  (a 4-line placeholder) and `assets/scripts/scan_secrets.py`
  (referenced by no other code path) have been removed. The
  `bootstrap.apply_universal` script list is now exactly
  `forbid_sensitive_files.py`, `prepush.py`, and
  `scan_mcp_config.py`.

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
in the next release; the fix shipped in `0.1.4` and remains in
`0.1.5`. Maintainers may want to yank `0.1.3` with reason
`Broken package assets; ai-repo-safety init fails after install`.

### Added
- Initial public release. CLI: doctor, install-missing, setup,
  init, install-hooks, scan, prepush, threat-model, incident,
  github-guard. Asset templates for universal, Python, and
  GitHub profiles. Opengrep rulepack with six rules.
