# MCP Safety Policy

Treat MCP servers as supply-chain dependencies and local execution surfaces.

Rules:

1. Use allowlist only.
2. Pin MCP server versions or commit SHAs where possible.
3. Do not store plaintext tokens in `.mcp.json`.
4. Do not commit `.mcp.json` or `claude_desktop_config.json`.
5. Do not allow new STDIO MCP servers without review.
6. Do not give one agent access to GitHub, filesystem, database, Jira, and shell unless necessary.
7. Prefer read-only tools.
8. Use one repo / one task / one scope per session.
9. Review tool descriptions for prompt injection.
10. Never let MCP tools read `.env`, private keys, credential files, or support/user exports.

Run:

```bash
python scripts/security/scan_mcp_config.py
```
