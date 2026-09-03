from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

from .util import current_platform, is_windows, project_root, run_cmd, which

# Pinned TruffleHog release for Windows install-tools. Bump after checking
# https://github.com/trufflesecurity/trufflehog/releases
TRUFFLEHOG_RELEASE = "3.97.1"


@dataclass
class ToolSpec:
    name: str
    command: str
    required: bool
    purpose: str
    install_hint: str
    version_args: tuple[str, ...] = ("--version",)
    category: str = "core"
    privacy_note: str = ""


TOOL_SPECS: list[ToolSpec] = [
    ToolSpec("Git", "git", True, "source control and hooks", "Install Git from official docs or OS package manager."),
    ToolSpec("Python", "python", True, "runtime; Python 3.12+ required", "Install Python 3.12+ or use `uv python install 3.12`."),
    ToolSpec("uv", "uv", True, "Python package/project manager", "Install uv from Astral official docs."),
    ToolSpec("uvx", "uvx", True, "run Python tools in isolated envs", "uvx is installed with uv; update/reinstall uv if missing."),
    ToolSpec("pre-commit", "pre-commit", False, "local commit hooks", "Install with `uv tool install pre-commit`."),
    ToolSpec("Gitleaks", "gitleaks", False, "fast secret scanning", "Install from Gitleaks official releases or package manager."),
    ToolSpec("TruffleHog", "trufflehog", False, "deep secret scanning and verification", "Install from TruffleHog official docs/releases."),
    ToolSpec("detect-secrets", "detect-secrets", False, "baseline-oriented secret scanner", "Install with `uv tool install detect-secrets`."),
    ToolSpec("Opengrep", "opengrep", False, "open-source SAST pattern engine", "Install from Opengrep official docs/releases; use current stable compatible version."),
    ToolSpec("Bandit", "bandit", False, "Python SAST", "Install with `uv tool install bandit`."),
    ToolSpec("Ruff", "ruff", False, "Python lint/security rules", "Install with `uv tool install ruff`."),
    ToolSpec("pip-audit", "pip-audit", False, "Python dependency vulnerability scanner", "Install with `uv tool install pip-audit`."),
    ToolSpec("OSV-Scanner", "osv-scanner", False, "open-source vulnerability scanner", "Install from OSV-Scanner official releases or package manager."),
    ToolSpec("GitHub CLI", "gh", False, "GitHub read guard backend", "Install GitHub CLI from official docs or package manager."),
    ToolSpec("git-filter-repo", "git-filter-repo", False, "clean leaked secrets from Git history", "Install with `uv tool install git-filter-repo` or OS package manager."),
    ToolSpec("GitLab CLI", "glab", False, "GitLab read guard backend", "Install GitLab CLI from official docs or package manager.", category="gitlab"),
    ToolSpec("gosec", "gosec", False, "Go static security analyzer", "Install from securego/gosec official releases or `go install github.com/securego/gosec/v2/cmd/gosec@latest` after checking the current release.", category="go"),
    ToolSpec("govulncheck", "govulncheck", False, "Go vulnerability analyzer", "Install from Go official tooling with `go install golang.org/x/vuln/cmd/govulncheck@latest` after checking Go docs.", category="go"),
    ToolSpec("cargo-audit", "cargo-audit", False, "Rust dependency vulnerability scanner", "Install from RustSec/cargo-audit official releases or `cargo install cargo-audit`.", category="rust"),
    ToolSpec("cargo-deny", "cargo-deny", False, "Rust dependency/license/advisory policy gate", "Install from EmbarkStudios/cargo-deny official releases or `cargo install cargo-deny`.", category="rust"),
    ToolSpec("ESLint", "eslint", False, "JavaScript/TypeScript lint and security-adjacent rules", "Use the project's package manager and official ESLint docs.", category="typescript"),
    ToolSpec("npm", "npm", False, "JavaScript package audit backend", "Install Node.js/npm from official Node.js distributions.", category="typescript"),
    ToolSpec("Snyk Agent Scan", "snyk-agent-scan", False, "AI agent, MCP, and skill scanner", "Install from Snyk Agent Scan official releases/docs.", category="agent-skill", privacy_note="may send agent metadata to Snyk cloud; require explicit opt-in before running"),
    ToolSpec("Cisco Skill Scanner", "skill-scanner", False, "AI skill prompt-injection and exfiltration scanner", "Install from cisco-ai-defense/skill-scanner official repository.", category="agent-skill"),
    ToolSpec("NVIDIA SkillSpector", "skillspector", False, "AI agent skill scanner with structured reports", "Install from NVIDIA/SkillSpector official repository.", category="agent-skill"),
]

PYTHON_TOOL_COMMANDS = {
    "pre-commit": "uv tool install pre-commit",
    "detect-secrets": "uv tool install detect-secrets",  # pragma: allowlist secret
    "bandit": "uv tool install bandit",
    "ruff": "uv tool install ruff",
    "pip-audit": "uv tool install pip-audit",
    "git-filter-repo": "uv tool install git-filter-repo",
}

WINDOWS_INSTALL = {
    "git": "winget install --id Git.Git -e",
    "python": "winget install --id Python.Python.3.12 -e",
    "uv": 'powershell -c "irm https://astral.sh/uv/install.ps1 | iex"',
    "uvx": 'powershell -c "irm https://astral.sh/uv/install.ps1 | iex"',
    "gitleaks": "winget install --id Gitleaks.Gitleaks -e",
    "osv-scanner": "winget install --id Google.OSVScanner -e",
    "gh": "winget install --id GitHub.cli -e",
    "trufflehog": (
        "Download "
        f"https://github.com/trufflesecurity/trufflehog/releases/download/v{TRUFFLEHOG_RELEASE}/"
        f"trufflehog_{TRUFFLEHOG_RELEASE}_windows_amd64.tar.gz "
        "(pinned; do not use /latest)"
    ),
    "opengrep": "npm install -g @opengrep/cli",
}

UNIX_INSTALL = {
    "git": "Install Git from official docs or OS package manager.",
    "python": "Install Python 3.12+ or use `uv python install 3.12`.",
    "uv": "Install uv from https://docs.astral.sh/uv/",
    "uvx": "uvx is installed with uv; update/reinstall uv if missing.",
    "gitleaks": "brew install gitleaks",
    "osv-scanner": "brew install osv-scanner",
    "gh": "brew install gh",
    "trufflehog": "brew install trufflehog",
    "opengrep": "npm install -g @opengrep/cli",
}


def install_one_liner(spec: ToolSpec) -> str:
    py_cmd = PYTHON_TOOL_COMMANDS.get(spec.command)
    if py_cmd:
        return py_cmd
    table = WINDOWS_INSTALL if is_windows() else UNIX_INSTALL
    return table.get(spec.command, spec.install_hint)


def check_python_312() -> tuple[bool, str]:
    version = sys.version_info
    ok = version >= (3, 12)
    return ok, f"{version.major}.{version.minor}.{version.micro}"


def check_tool(spec: ToolSpec) -> tuple[bool, str]:
    if spec.command == "python" and is_windows() and not which("python") and which("py"):
        code, out, err = run_cmd(["py", "-3", "--version"], timeout=20)
        if code == 0:
            version = (out or err or "py -3").strip().splitlines()[0]
            return True, version
    path = which(spec.command)
    if not path:
        return False, "missing"
    code, out, err = run_cmd([spec.command, *spec.version_args], timeout=20)
    if code != 0:
        return False, (err or out or f"exit:{code}").strip()
    version = (out or err or path).strip().splitlines()[0] if (out or err) else path
    if len(version) > 100:
        version = version[:100] + "..."
    return True, version


def doctor(*, agent_plan: bool = False, json_out: bool = False, target: str | Path | None = None) -> int:
    root = project_root(target or ".")
    rows: list[tuple[str, str, str]] = [("Tool", "Status", "Details")]
    missing_required: list[ToolSpec] = []
    missing_optional: list[ToolSpec] = []
    tool_rows: list[dict] = []

    py_ok, py_ver = check_python_312()
    if not py_ok:
        rows.append(("Python version", "FAIL", f"{py_ver}; Python 3.12+ required"))
    else:
        rows.append(("Python version", "OK", py_ver))

    for spec in TOOL_SPECS:
        ok, details = check_tool(spec)
        status = "OK" if ok else ("FAIL" if spec.required else "MISSING")
        install = install_one_liner(spec)
        display = details if ok else install
        if spec.privacy_note:
            display = f"{display}; {spec.privacy_note}"
        rows.append((spec.name, status, display))
        tool_rows.append(
            {
                "name": spec.name,
                "command": spec.command,
                "status": status,
                "details": details if ok else display,
                "install": install,
                "required": spec.required,
            }
        )
        if not ok and spec.required:
            missing_required.append(spec)
        elif not ok:
            missing_optional.append(spec)

    uv_lock = (root / "uv.lock").exists()
    osv_ok = bool(which("osv-scanner"))
    tag_gate_ok = (not uv_lock) or osv_ok
    if uv_lock and not osv_ok:
        rows.append(
            (
                "OSV-Scanner (tag gate)",
                "FAIL",
                f"{install_one_liner(next(s for s in TOOL_SPECS if s.command == 'osv-scanner'))}; uv.lock present so tag gate requires osv-scanner",
            )
        )
        missing_required.append(next(s for s in TOOL_SPECS if s.command == "osv-scanner"))

    missing_payload = [
        {"name": spec.name, "install": install_one_liner(spec)}
        for spec in missing_required + missing_optional
    ]
    # Dedupe osv-scanner if added twice.
    seen: set[str] = set()
    unique_missing: list[dict] = []
    for item in missing_payload:
        if item["name"] in seen:
            continue
        seen.add(item["name"])
        unique_missing.append(item)

    payload = {
        "platform": current_platform(),
        "python_executable": sys.executable,
        "python": {"ok": py_ok, "version": py_ver},
        "target": str(root),
        "tools": tool_rows,
        "missing": unique_missing,
        "tag_gate": {"uv_lock": uv_lock, "osv_scanner": osv_ok, "ok": tag_gate_ok},
        "invoke": [
            "py -3 -m ai_repo_safety",
            "python -m ai_repo_safety",
            "uvx ai-repo-safety",
        ],
    }

    if json_out:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        if not py_ok or missing_required:
            return 2
        return 0

    print("AI Repo Safety Doctor")
    print(f"Platform: {current_platform()}")
    print(f"Python executable: {sys.executable}")
    print()

    from .util import print_table
    print_table(rows)
    print()

    if missing_required or agent_plan:
        print("Agent install plan (one command per missing tool):")
        for item in unique_missing:
            print(f"- {item['name']}: `{item['install']}`")
        print()
        print("Canonical invoke: `py -3 -m ai_repo_safety` / `python -m ai_repo_safety` / `uvx ai-repo-safety`.")
        print("Re-run `python -m ai_repo_safety doctor --target .` after installation.")

    if not py_ok or missing_required:
        return 2
    return 0



def install_missing_tools(*, dry_run: bool = False, yes: bool = False) -> int:
    """Install Python helper tools and System binaries.

    Safety posture: this function never mutates the host system
    unless the caller passes yes=True. The legacy dry_run=True
    flag is preserved for backward compatibility with the
    `install-missing --dry-run` CLI alias.
    """
    from pathlib import Path

    if not yes and not dry_run:
        print(
            "[repo-safety] refusing to install tools without explicit --yes. "
            "Use --dry-run to print the plan, or --yes to perform the install."
        )
        return 2

    is_win = is_windows()
    failures = 0
    apply = yes and not dry_run

    if not which("uv"):
        print("[repo-safety] uv is missing; cannot install Python tools. Run doctor and install uv first.")
        failures += 1
    else:
        for command, install_cmd in PYTHON_TOOL_COMMANDS.items():
            if which(command):
                print(f"[repo-safety] {command} already installed")
                continue
            args = install_cmd.split()
            print(f"[repo-safety] {'would run' if not apply else 'running'}: {install_cmd}")
            if apply:
                code, out, err = run_cmd(args, timeout=600)
                if out:
                    print(out.rstrip())
                if err:
                    print(err.rstrip())
                if code != 0:
                    failures += 1
                    print(f"[repo-safety] failed to install {command}")

    system_tools = ["gitleaks", "trufflehog", "opengrep", "osv-scanner", "gh"]
    
    for tool in system_tools:
        if which(tool):
            print(f"[repo-safety] {tool} already installed")
            continue
            
        print(f"[repo-safety] installing {tool}...")
        if dry_run:
            print(f"  would install {tool}")
            continue

        success = False
        try:
            if tool == "gitleaks":
                if is_win:
                    c, o, e = run_cmd(["winget", "install", "--id", "Gitleaks.Gitleaks", "-e", "--accept-source-agreements", "--accept-package-agreements"])
                    success = (c == 0)
                else:
                    c, o, e = run_cmd(["brew", "install", "gitleaks"])
                    success = (c == 0)
            
            elif tool == "osv-scanner":
                if is_win:
                    c, o, e = run_cmd(["winget", "install", "--id", "Google.OSVScanner", "-e", "--accept-source-agreements", "--accept-package-agreements"])
                    success = (c == 0)
                else:
                    c, o, e = run_cmd(["brew", "install", "osv-scanner"])
                    success = (c == 0)
                    
            elif tool == "gh":
                if is_win:
                    c, o, e = run_cmd(["winget", "install", "--id", "GitHub.cli", "-e", "--accept-source-agreements", "--accept-package-agreements"])
                    success = (c == 0)
                else:
                    c, o, e = run_cmd(["brew", "install", "gh"])
                    success = (c == 0)
                    
            elif tool == "opengrep":
                if which("npm"):
                    c, o, e = run_cmd(["npm", "install", "-g", "@opengrep/cli"])
                    success = (c == 0)
                else:
                    print("[repo-safety] npm is missing; cannot install opengrep automatically.")
                    
            elif tool == "trufflehog":
                if is_win:
                    print("[repo-safety] downloading pinned trufflehog for windows...")
                    import urllib.request
                    import tarfile
                    import io
                    try:
                        download_url = (
                            "https://github.com/trufflesecurity/trufflehog/releases/download/"
                            f"v{TRUFFLEHOG_RELEASE}/trufflehog_{TRUFFLEHOG_RELEASE}_windows_amd64.tar.gz"
                        )
                        print(f"[repo-safety] downloading trufflehog from {download_url}...")
                        with urllib.request.urlopen(download_url) as response:  # nosec B310
                            tar_bytes = response.read()
                        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
                            target_dir = Path.home() / ".local" / "bin"
                            target_dir.mkdir(parents=True, exist_ok=True)
                            member = tar.getmember("trufflehog.exe")
                            f = tar.extractfile(member)
                            if f:
                                (target_dir / "trufflehog.exe").write_bytes(f.read())
                                print(f"[repo-safety] trufflehog installed to {target_dir}. Make sure it is in your PATH!")
                                success = True
                    except Exception as e:
                        print(f"[repo-safety] error downloading trufflehog: {e}")
                        success = False
                else:
                    c, o, e = run_cmd(["brew", "install", "trufflehog"])
                    success = (c == 0)
                    
        except Exception as ex:
            print(f"[repo-safety] exception installing {tool}: {ex}")
            
        if not success:
            print(f"[repo-safety] failed to install {tool}")
            failures += 1
            
    return 1 if failures else 0
