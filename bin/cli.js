#!/usr/bin/env node
'use strict';

// ai-repo-safety npm wrapper.
//
// The CLI is implemented in Python. This wrapper picks the matching
// PyPI release for this exact npm package version, so that
// `npm install -g ai-repo-safety@0.1.3` always runs Python
// `ai-repo-safety==0.1.3` instead of an unpinned `latest` tag.
//
// Resolution order:
//   1. uvx (zero-install, isolated env) with pinned version
//   2. python -m ai_repo_safety
//   3. python3 -m ai_repo_safety
//
// If none is available, print a single, copy-pasteable install hint
// and exit 127 (the conventional `command not found` code).

const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');

const args = process.argv.slice(2);
const isWindows = process.platform === 'win32';

// Read the version from the npm package manifest. The package.json
// file is co-located with bin/cli.js at the repo root, but in installed
// npm packages it is at the parent of the bin/ directory.
function readPackageVersion() {
  const candidates = [
    path.resolve(__dirname, '..', 'package.json'),
    path.resolve(process.cwd(), 'package.json'),
  ];
  for (const p of candidates) {
    try {
      const text = fs.readFileSync(p, 'utf8');
      const pkg = JSON.parse(text);
      if (typeof pkg.version === 'string' && pkg.version.length > 0) {
        return pkg.version;
      }
    } catch (_) {
      // try next candidate
    }
  }
  // Last resort: refuse to silently fall back to an unpinned resolution.
  throw new Error(
    'ai-repo-safety npm wrapper: could not locate a package.json with a ' +
    '`version` field. Refusing to resolve a version from a non-package context.',
  );
}

function run(cmd, cmdArgs) {
  const result = spawnSync(cmd, cmdArgs, {
    stdio: 'inherit',
    shell: isWindows,
  });

  if (result.error) {
    if (result.error.code === 'ENOENT') {
      return { found: false, code: null };
    }
    return { found: true, code: 1 };
  }

  if (typeof result.status === 'number') {
    return { found: true, code: result.status };
  }

  if (typeof result.signal === 'string') {
    return { found: true, code: 1 };
  }

  return { found: false, code: null };
}

function main() {
  const version = readPackageVersion();
  const pinSpec = `ai-repo-safety==${version}`;

  const uvx = run('uvx', [pinSpec, ...args]);
  if (uvx.found) process.exit(uvx.code);

  const py = run('python', ['-m', 'ai_repo_safety', ...args]);
  if (py.found) process.exit(py.code);

  const py3 = run('python3', ['-m', 'ai_repo_safety', ...args]);
  if (py3.found) process.exit(py3.code);

  const cmdLine = ['uvx', pinSpec, ...args].join(' ');
  process.stderr.write(
    [
      'Error: ai-repo-safety requires Python 3.12+ and either uvx or an installed Python package.',
      '',
      'Install uv:',
      '  https://docs.astral.sh/uv/getting-started/installation/',
      '',
      `Then run:`,
      `  ${cmdLine}`,
      '',
      'Or install the matching Python release:',
      `  pip install ${pinSpec}`,
      '',
    ].join('\n'),
  );
  process.exit(127);
}

main();
