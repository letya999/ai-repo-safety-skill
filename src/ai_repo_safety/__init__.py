from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ai-repo-safety")
except PackageNotFoundError:
    # Source-tree usage (e.g. `python -m ai_repo_safety` from a checkout
    # before `pip install` or `uv build`) has no installed metadata.
    # Fall back to a clearly non-semver placeholder so callers that
    # compare versions do not silently treat source as "0.1.0".
    __version__ = "0.0.0+local"

__all__ = ["__version__"]
