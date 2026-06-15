from __future__ import annotations

import sys
from dataclasses import dataclass

from .util import current_platform, is_windows, run_cmd, which


@dataclass
class ToolSpec:
    name: str
    command: str
    required: bool
    purpose: str
    install_hint: str
    version_args: tuple[str, ...] = ("--version",)


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
]

PYTHON_TOOL_COMMANDS = {
    "pre-commit": "uv tool install pre-commit",
    "detect-secrets": "uv tool install detect-secrets",  # pragma: allowlist secret
    "bandit": "uv tool install bandit",
    "ruff": "uv tool install ruff",
    "pip-audit": "uv tool install pip-audit",
    "git-filter-repo": "uv tool install git-filter-repo",
}


def check_python_312() -> tuple[bool, str]:
    version = sys.version_info
    ok = version >= (3, 12)
    return ok, f"{version.major}.{version.minor}.{version.micro}"


def check_tool(spec: ToolSpec) -> tuple[bool, str]:
    path = which(spec.command)
    if not path:
        return False, "missing"
    code, out, err = run_cmd([spec.command, *spec.version_args], timeout=20)
    version = (out or err or path).strip().splitlines()[0] if (out or err) else path
    if len(version) > 100:
        version = version[:100] + "..."
    return True, version


def doctor(*, agent_plan: bool = False) -> int:
    print("AI Repo Safety Doctor")
    print(f"Platform: {current_platform()}")
    print(f"Python executable: {sys.executable}")
    print()

    rows: list[tuple[str, str, str]] = [("Tool", "Status", "Details")]
    missing_required: list[ToolSpec] = []
    missing_optional: list[ToolSpec] = []

    py_ok, py_ver = check_python_312()
    if not py_ok:
        rows.append(("Python version", "FAIL", f"{py_ver}; Python 3.12+ required"))
    else:
        rows.append(("Python version", "OK", py_ver))

    for spec in TOOL_SPECS:
        ok, details = check_tool(spec)
        status = "OK" if ok else ("FAIL" if spec.required else "MISSING")
        rows.append((spec.name, status, details if ok else spec.install_hint))
        if not ok and spec.required:
            missing_required.append(spec)
        elif not ok:
            missing_optional.append(spec)

    from .util import print_table
    print_table(rows)
    print()

    if missing_required or agent_plan:
        print("Agent install plan:")
        print("1. For every missing tool, search the official documentation or official releases for the current stable compatible version.")
        print("2. Prefer uv/uvx for Python tools and official OS package managers for system binaries.")
        print("3. Do not install random blog snippets, curl|bash commands from untrusted pages, or unpinned binaries.")
        print("4. Re-run `ai-repo-safety doctor` after installation.")
        print()
        from .util import is_windows
        is_win = is_windows()
        for spec in missing_required + missing_optional:
            py_cmd = PYTHON_TOOL_COMMANDS.get(spec.command)
            if py_cmd:
                print(f"- {spec.name}: try `{py_cmd}`; if it fails, search official docs for stable compatible install.")
            else:
                hint = spec.install_hint
                if spec.name == "Opengrep":
                    hint = "run `irm https://raw.githubusercontent.com/opengrep/opengrep/main/install.ps1 | iex` (PowerShell) or `npm install -g @opengrep/cli`" if is_win else "run `curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash` or `npm install -g @opengrep/cli`"
                elif spec.name == "Gitleaks":
                    hint = "run `winget install --id Gitleaks.Gitleaks -e` or `scoop install gitleaks`" if is_win else "run `brew install gitleaks` or OS package manager"
                elif spec.name == "OSV-Scanner":
                    hint = "run `winget install --id Google.OSVScanner -e` or `scoop install osv-scanner`" if is_win else "run `brew install osv-scanner` or OS package manager"
                elif spec.name == "TruffleHog":
                    hint = "Not in winget/scoop. Find latest version via `curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest` and download the windows_amd64.zip binary" if is_win else "run `brew install trufflehog` or download binary"
                elif spec.name == "GitHub CLI":
                    hint = "run `winget install --id GitHub.cli -e` or `scoop install gh`" if is_win else "run `brew install gh` or OS package manager"
                print(f"- {spec.name}: {hint}")

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
                    print("[repo-safety] downloading trufflehog for windows...")
                    import urllib.request
                    import tarfile
                    import io
                    import json
                    try:
                        # 1. Fetch latest release info to get the actual version and download URL
                        req = urllib.request.Request("https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest", headers={"User-Agent": "Mozilla/5.0"})
                        with urllib.request.urlopen(req) as r:  # nosec B310
                            release_data = json.loads(r.read())
                        # Find asset ending with windows_amd64.tar.gz
                        download_url = None
                        for asset in release_data.get("assets", []):
                            if asset.get("name", "").endswith("windows_amd64.tar.gz"):
                                download_url = asset.get("browser_download_url")
                                break
                        if not download_url:
                            download_url = "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_windows_amd64.tar.gz"
                        
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
