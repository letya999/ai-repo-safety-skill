#!/usr/bin/env node
'use strict';

const { spawn } = require('child_process');

const args = process.argv.slice(2);

function run(cmd, cmdArgs) {
  return new Promise((resolve) => {
    const child = spawn(cmd, cmdArgs, { stdio: 'inherit', shell: process.platform === 'win32' });
    child.on('exit', (code) => resolve(code ?? 1));
    child.on('error', () => resolve(null));
  });
}

async function main() {
  // Prefer uvx (uv's isolated tool runner) — zero-install Python env.
  let code = await run('uvx', ['ai-repo-safety@latest', ...args]);
  if (code !== null) {
    process.exit(code);
  }

  // Fallback: python -m ai_repo_safety (if installed via pip).
  code = await run('python', ['-m', 'ai_repo_safety', ...args]);
  if (code !== null) {
    process.exit(code);
  }

  // python3 variant on systems where python3 is the only alias.
  code = await run('python3', ['-m', 'ai_repo_safety', ...args]);
  if (code !== null) {
    process.exit(code);
  }

  console.error([
    'Error: ai-repo-safety requires Python 3.12+ and either uv or pip.',
    '',
    'Install uv (recommended):',
    '  curl -LsSf https://astral.sh/uv/install.sh | sh',
    '  # then run: uvx ai-repo-safety ' + args.join(' '),
    '',
    'Or install via pip:',
    '  pip install ai-repo-safety',
  ].join('\n'));
  process.exit(1);
}

main();
