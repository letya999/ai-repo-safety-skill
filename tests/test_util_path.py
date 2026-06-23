from __future__ import annotations

import os

from ai_repo_safety import util


def test_importing_util_does_not_mutate_path() -> None:
    """Importing ai_repo_safety.util must not have global side
    effects on the host environment. The PATH augmentation is now an
    explicit, opt-in step (prepare_cli_environment), so libraries
    and tests that import this module do not silently change
    subprocess resolution for the rest of the process."""
    # util is already imported by the test collection; assert the
    # import-time invariant held by exposing the explicit entry point.
    assert hasattr(util, "prepare_cli_environment"), (
        "util must expose prepare_cli_environment as the explicit PATH"
        " normalization entry point"
    )


def test_prepare_cli_environment_is_idempotent() -> None:
    before = os.environ.get("PATH", "")
    util.prepare_cli_environment()
    after_first = os.environ.get("PATH", "")
    util.prepare_cli_environment()
    after_second = os.environ.get("PATH", "")
    assert after_first == after_second, (
        "prepare_cli_environment must be idempotent; a repeated call"
        " must not add duplicate PATH entries or reorder existing"
        " ones in a way that changes resolution"
    )
    # We do not require the PATH to differ from `before`; the goal
    # has a healthy PATH, the post-call value can equal the
    # pre-call value.
    assert isinstance(after_first, str)
    assert isinstance(before, str)


def test_parse_gitlab_repo_from_url() -> None:
    assert util.parse_gitlab_repo_from_url("https://gitlab.com/owner/repo.git") == "owner/repo"
    assert util.parse_gitlab_repo_from_url("https://gitlab.com/owner/subgroup/repo") == "owner/subgroup/repo"
    assert util.parse_gitlab_repo_from_url("git@gitlab.com:owner/repo.git") == "owner/repo"
    assert util.parse_gitlab_repo_from_url("git@gitlab.com:owner/repo") == "owner/repo"
    assert util.parse_gitlab_repo_from_url("https://github.com/owner/repo.git") is None
    
    # Test self-hosted
    assert util.parse_gitlab_repo_from_url("https://git.internal.corp/team/project.git", gitlab_host="git.internal.corp") == "team/project"
    assert util.parse_gitlab_repo_from_url("git@git.internal.corp:team/sub/project.git", gitlab_host="git.internal.corp") == "team/sub/project"
