"""Parity comparison: GitHub Guard vs GitLab Guard.

This module maps what each guard should have in common and where
they legitimately differ, so divergence can be caught by tests.

Common contract (both guards must satisfy):
  validate_request -> (bool, str, int, str)  exit codes
  read_*           -> int  (0=ok, 1=err, 2=blocked)
  check_text       -> int  (0=clean, 1=injection, 2=ioerr, 4=escape)
  sanitize_payload -> (payload, warnings, count)
  redact           -> (str, int)
  has_prompt_injection -> list[str]

GitHub-specific:
  - uses `gh api`
  - does NOT URL-encode repo (owner/repo format handled by `gh`)
  - policy key: github_read_guard
  - resources: issues, pulls, prs, branches, commits, mrs, merge_requests

GitLab-specific:
  - uses `glab api`
  - MUST URL-encode repo (namespace%2Fproject for GitLab API v4)
  - policy key: gitlab_read_guard
  - resources: issues, merge_requests, mrs, branches, commits
  - additional config: gitlab_host (for self-hosted)
  - additional secret pattern: glpat-*, glcbt-*
"""
