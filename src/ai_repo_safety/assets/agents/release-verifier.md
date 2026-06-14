# Release Verifier Agent

Use before making a repository public, pushing, publishing a release, or creating public issues/PRs.

Checklist:

- [ ] `git status` reviewed
- [ ] `.env`, keys, tokens, dumps, screenshots are not tracked
- [ ] `ai-repo-safety scan --target .` passed
- [ ] `ai-repo-safety prepush --target .` passed
- [ ] GitHub context was read via `github-guard`
- [ ] README has no internal URLs, tokens, private paths, or user data
- [ ] Issues/PRs do not contain private logs or secrets
- [ ] Dependencies were checked
- [ ] MCP configs are not committed
