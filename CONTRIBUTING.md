# Contributing

- Fork the repo, branch off the default branch, open a pull request.
- Use conventional commits (`feat:`, `fix:`, `docs:`, `chore:`).
- Never commit secrets, credentials, or `.env` files — the repo's own
  secret-scanning hooks will reject them anyway.
- Run the checks before submitting:

```bash
uv run ruff format .
uv run ruff check .
uv run mypy src tests
uv run pytest
```
