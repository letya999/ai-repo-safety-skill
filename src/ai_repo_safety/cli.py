from __future__ import annotations

import argparse

from . import __version__
from .bootstrap import init_project, setup_project
from .github_guard import check_text, read_github, validate_request
from .hooks import install_hooks
from .incident import create as create_incident
from .scanner import prepush, scan
from .threat_model import generate as generate_threat_model
from .tools import doctor
from .util import project_root
from .verify_release import verify_release


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ai-repo-safety", description="AI/vibe-coding repo safety skill CLI")
    parser.add_argument("--version", action="version", version=f"ai-repo-safety {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("doctor", help="check Git/Python/uv/uvx/scanners and print agent install plan")
    p.add_argument("--agent-plan", action="store_true", help="always print agent install plan")

    p = sub.add_parser("install-missing", help="Install missing Python and system tools")
    p.add_argument("--dry-run", action="store_true")

    p = sub.add_parser("setup", help="plan and optionally apply repo safety bootstrap (plan-only by default)")
    p.add_argument("--target", default=".")
    p.add_argument("--python", choices=["auto", "yes", "no"], default="auto")
    p.add_argument("--github", choices=["auto", "yes", "no"], default="auto")
    p.add_argument("--overwrite", action="store_true")
    p.add_argument(
        "--apply",
        action="store_true",
        help="actually perform the optional steps; default is plan-only",
    )
    p.add_argument(
        "--install-tools",
        action="store_true",
        help="in --apply mode, run the system/Python tool installer",
    )
    p.add_argument(
        "--run-hooks",
        action="store_true",
        help="in --apply mode, install the local git pre-push hook",
    )
    p.add_argument(
        "--configure-github",
        action="store_true",
        help="in --apply mode, call the GitHub API to enable secret scanning and push protection",
    )
    p.add_argument(
        "--yes",
        action="store_true",
        help="required confirmation flag for any --apply mutation",
    )

    p = sub.add_parser("init", help="apply repo safety assets")
    p.add_argument("--target", default=".")
    p.add_argument("--python", choices=["auto", "yes", "no"], default="auto")
    p.add_argument("--github", choices=["auto", "yes", "no"], default="auto")
    p.add_argument("--overwrite", action="store_true")

    p = sub.add_parser("install-hooks", help="install Git pre-push hook (refuses to overwrite existing unmanaged hooks)")
    p.add_argument("--target", default=".")
    p.add_argument(
        "--chain",
        action="store_true",
        help="keep any existing pre-push hook and append a managed block after it",
    )
    p.add_argument(
        "--overwrite",
        action="store_true",
        help="replace any existing pre-push hook with the managed one",
    )
    p.add_argument(
        "--hooks-path",
        default=None,
        help="custom hooks directory (defaults to .git/hooks)",
    )

    p = sub.add_parser("scan", help="run available local scans")
    p.add_argument("--target", default=".")
    p.add_argument("--strict", action="store_true", help="missing recommended scanners fail the run")

    p = sub.add_parser("prepush", help="run pre-push gate")
    p.add_argument("--target", default=".")

    p = sub.add_parser("threat-model", help="create lightweight STRIDE threat model template")
    p.add_argument("--target", default=".")
    p.add_argument("--overwrite", action="store_true")

    p = sub.add_parser("incident", help="create incident cleanup doc")
    p.add_argument("--target", default=".")
    p.add_argument("--type", default="secret-leak")
    p.add_argument("--overwrite", action="store_true")

    p = sub.add_parser("verify-release", help="verify the project is ready for a new release")
    p.add_argument("--target", default=".")
    p.add_argument("--version", required=True, help="expected release version, e.g. 0.1.4")
    p.add_argument("--skip-build", action="store_true", help="do not run uv build")

    gh = sub.add_parser("github-guard", help="guard reads of GitHub commits/PRs/branches/issues")
    gh_sub = gh.add_subparsers(dest="gh_cmd", required=True)

    p = gh_sub.add_parser("validate", help="validate if a GitHub read is allowed by policy")
    p.add_argument("--target", default=".")
    p.add_argument("--repo", required=True)
    p.add_argument("--resource", required=True, choices=["issues", "pulls", "prs", "branches", "commits", "mrs", "merge_requests"])
    p.add_argument("--reason")
    p.add_argument("--limit", type=int)

    p = gh_sub.add_parser("read", help="read GitHub data through policy and redaction guard")
    p.add_argument("--target", default=".")
    p.add_argument("--repo", required=True)
    p.add_argument("--resource", required=True, choices=["issues", "pulls", "prs", "branches", "commits", "mrs", "merge_requests"])
    p.add_argument("--reason")
    p.add_argument("--limit", type=int)
    p.add_argument("--allow-prompt-injection-risk", action="store_true")

    p = gh_sub.add_parser("check-text", help="scan text/file for prompt-injection-like patterns and redact secrets")
    p.add_argument("--target", default=".")
    p.add_argument("--file")
    p.add_argument("--text")

    return parser


def main(argv: list[str] | None = None) -> int:
    import sys

    # Normalize the CLI's PATH so subprocesses can find venv-installed
    # tools, opengrep, and the user's local bin. This is an explicit,
    # idempotent side effect of running the CLI; importing the package
    # must not have triggered it.
    from .util import prepare_cli_environment

    prepare_cli_environment()

    if sys.stdout.encoding.lower() != 'utf-8':
        try:
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
        except AttributeError:
            pass

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "doctor":
        return doctor(agent_plan=args.agent_plan)
    elif args.cmd == "install-missing":
        from ai_repo_safety.tools import install_missing_tools
        return install_missing_tools(dry_run=args.dry_run)
    if args.cmd == "setup":
        return setup_project(
            args.target,
            python=args.python,
            github=args.github,
            overwrite=args.overwrite,
            mode="apply" if args.apply else "plan",
            install_tools=args.install_tools,
            configure_github=args.configure_github,
            run_hooks=args.run_hooks,
            yes=args.yes,
        )
    if args.cmd == "init":
        return init_project(args.target, python=args.python, github=args.github, overwrite=args.overwrite)
    if args.cmd == "install-hooks":
        return install_hooks(
            args.target,
            overwrite=args.overwrite,
            chain=args.chain,
            hooks_path=args.hooks_path,
        )
    if args.cmd == "scan":
        return scan(args.target, strict=args.strict)
    if args.cmd == "prepush":
        return prepush(args.target)
    if args.cmd == "threat-model":
        return generate_threat_model(args.target, overwrite=args.overwrite)
    if args.cmd == "incident":
        return create_incident(args.target, incident_type=args.type, overwrite=args.overwrite)
    if args.cmd == "verify-release":
        return verify_release(
            args.target,
            args.version,
            skip_build=args.skip_build,
        )
    if args.cmd == "github-guard":
        root = project_root(args.target)
        if args.gh_cmd == "validate":
            ok, msg, limit, resource = validate_request(root, args.repo, args.resource, args.reason, args.limit)
            print({"allowed": ok, "message": msg, "resource": resource, "effective_limit": limit})
            return 0 if ok else 2
        if args.gh_cmd == "read":
            return read_github(root, args.repo, args.resource, args.reason, args.limit, args.allow_prompt_injection_risk)
        if args.gh_cmd == "check-text":
            return check_text(root, args.file, args.text)

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
