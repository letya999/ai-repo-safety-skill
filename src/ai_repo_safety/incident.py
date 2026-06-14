from __future__ import annotations

from pathlib import Path
from .util import asset_text, project_root, write_text


def create(target: str | Path, incident_type: str = "secret-leak", *, overwrite: bool = False) -> int:
    root = project_root(target)
    dest = root / "docs" / f"incident-{incident_type}.md"
    template = asset_text("docs/incident-cleanup.md")
    if write_text(dest, template, overwrite=overwrite):
        print(f"[repo-safety] created {dest}")
    else:
        print(f"[repo-safety] kept existing {dest}")
    print("[repo-safety] rotate/revoke exposed secrets before history cleanup")
    return 0
