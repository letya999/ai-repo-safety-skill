from __future__ import annotations

from pathlib import Path
from .util import asset_text, project_root, write_text


def generate(target: str | Path, *, overwrite: bool = False) -> int:
    root = project_root(target)
    path = root / "docs" / "threat-model.md"
    if write_text(path, asset_text("docs/threat-model-template.md"), overwrite=overwrite):
        print(f"[repo-safety] created {path}")
    else:
        print(f"[repo-safety] kept existing {path}")
    return 0
