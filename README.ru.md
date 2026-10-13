<p align="center">
  <a href="README.md">English</a> · <strong>Русский</strong>
</p>

# AI Repo Safety Skill

Один публичный скилл + репозиторий ассетов для упрочнения AI/vibe-coded
проектов перед коммитом, перед пушем и перед публикацией на GitHub.

Проект рассчитан на **Python 3.12**, **uv** и **uvx**, работает на
**Windows, macOS и Linux** и по умолчанию использует только
бесплатные / open-source / community-инструменты.

## Что это даёт

- один устанавливаемый скилл: `SKILL.md`
- один Python CLI: `ai-repo-safety`
- безопасный bootstrap репозитория до первого коммита
- denylist секретных файлов
- интеграции Gitleaks / TruffleHog / detect-secrets
- SAST-профиль на Opengrep, без Semgrep как обязательной зависимости
- харденинг Python через Bandit, Ruff, pip-audit, pytest, примеры pydantic-settings
- инвентарь сканеров для Go, Rust, JavaScript/TypeScript и Angular
- опциональные сканеры AI-скиллов: Snyk Agent Scan, Cisco Skill Scanner, NVIDIA SkillSpector
- workflow харденинга публичных GitHub-репозиториев
- шаблоны GitLab CI и поддержка SaaS/Self-Hosted конфигураций
- read guard для GitHub и GitLab: коммиты, PR, ветки, issues, merge requests
- проверки безопасности MCP-конфигов
- лёгкие STRIDE threat-model шаблоны

## Установка скилла

```bash
npx skills add letya999/ai-repo-safety-skill
```

Или склонируйте в каталог скиллов агента:

```bash
git clone https://github.com/letya999/ai-repo-safety-skill.git .agents/skills/ai-repo-safety
```

## Установка CLI

```bash
# запуск без установки
uvx ai-repo-safety --help

# или через pip
pip install ai-repo-safety
```

## Основные команды

```bash
# read-only проверка окружения
ai-repo-safety check

# plan-only bootstrap: по умолчанию ничего не ставит и не меняет.
# Для конкретной мутации нужны --apply --yes и соответствующий opt-in флаг.
ai-repo-safety bootstrap --plan

# локальная установка хуков; отказывается перезаписывать чужой
# существующий hook без --overwrite (или --chain для добавления)
ai-repo-safety hooks install

# repo-scoped agent hooks: Codex читает .codex/hooks.json,
# Claude Code — .claude/settings.json, OpenCode — .opencode/plugins/,
# Antigravity — .agents/hooks.json в workspace
ai-repo-safety agent-hooks install

# сканы
ai-repo-safety scan secrets
ai-repo-safety scan sast
ai-repo-safety scan supply-chain

# GitHub read guard — всегда с явным --reason
ai-repo-safety github-read --reason "review PR 12" --repo owner/name

# threat model и шаблоны инцидентов
ai-repo-safety threat-model init

# предрелизная проверка
ai-repo-safety release-check
```

## AI-ассистенты

- **Claude Code**: скилл кладётся в `.claude/skills/` или ставится через `npx skills add`.
- **Codex CLI / OpenCode**: каталог `.agents/skills/` или `~/.codex/skills/`.
- **Cursor**: импорт как project rule / skill.
- Полная карта интеграций — в [README.md](README.md) (English).

## Философия

- По умолчанию только бесплатные OSS/community инструменты.
- Любая мутация — только по явным opt-in флагам.
- Read guard для GitHub/GitLab: чтение публичных данных требует `--reason`,
  всё логируется.

## Важные ограничения

- Сканеры — это сетка, а не доказательство: нулевой результат не гарантирует
  отсутствие уязвимостей.
- Не печатайте и не коммитьте секреты; `.env*` и ключи всегда вне git.
- Подробности и границы — в английской версии [README.md](README.md).

## License

[MIT](LICENSE)
