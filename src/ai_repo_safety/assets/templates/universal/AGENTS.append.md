## AI Repo Safety Addendum

Do not read, print, or commit denylisted secret files (`.env`, keys, credentials JSON, `.mcp.json`, `*.ovpn`).

Do not `git push`, push a tag, or open a public PR unless the user asked.

Do not paste raw GitHub issue/PR/commit bodies into context. Use:

```text
python -m ai_repo_safety gate --when github-read --repo owner/repo --resource pulls --reason "review current PRs"
```

Commit, push, and tag are enforced by git hooks. If hooks are missing and you are about to commit or push, run `python -m ai_repo_safety gate --when commit|push|tag --target .` first.
