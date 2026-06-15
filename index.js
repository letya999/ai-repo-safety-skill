'use strict';

// Programmatic entry point for the `ai-repo-safety` npm package.
//
// The CLI is implemented in Python. This shim is intentionally a
// no-op proxy so that `require('ai-repo-safety')` does not fail
// with `MODULE_NOT_FOUND` on installations that only ship the
// shim binary and not the Python source.
//
// The intended way to invoke the CLI is via the `bin/cli.js`
// wrapper, which spawns `uvx ai-repo-safety==<version>` with the
// exact same Python release as the npm version. Code that wants
// the Python CLI entrypoint from a Node program can spawn the
// `bin/cli.js` child the same way as a shell user would.
//
// This stub exists only to satisfy `package.json.main` for tools
// that introspect it (for example, `npm ls` and some IDEs). It
// does not export a runnable API.

module.exports = {};
