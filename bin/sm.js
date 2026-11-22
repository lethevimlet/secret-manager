#!/usr/bin/env node
// sm: a bash-compatible shell that substitutes secret placeholders and redacts
// secrets from output. Use it wherever bash is used:
//   sm                      interactive shell
//   sm -c 'curl -H "Authorization: Bearer $API_KEY" ...'
//   sm script.sh args...
//   SHELL=/path/to/sm <agent>
// Manage secrets with smctl.
import { runShell } from '../src/shell.js';

try {
  const code = await runShell(process.argv.slice(2));
  process.exit(code);
} catch (err) {
  process.stderr.write(`sm: ${err.message}\n`);
  process.exit(2);
}
