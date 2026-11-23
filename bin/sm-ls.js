#!/usr/bin/env node
// sm-ls: list secret names (never values), for people and agents.
//   sm-ls              scope, name, category, note
//   sm-ls github       only entries whose name, category or note contains "github"
//   sm-ls -s work      only scope "work" (-s default = the default scope)
//   sm-ls -q           names only
//   sm-ls --json       machine-readable
import { listSecrets } from '../src/backend.js';

const args = process.argv.slice(2);
if (args.includes('-h') || args.includes('--help')) {
  process.stdout.write('usage: sm-ls [SEARCH] [-s SCOPE[,SCOPE]] [-q] [--json]\nLists secret names, scopes, categories and notes. Never values.\nUse a scope\'s secrets with: sm -s SCOPE\n');
  process.exit(0);
}
let only = null;
for (const f of ['-s', '--scope']) {
  const i = args.indexOf(f);
  if (i !== -1) {
    only = (args[i + 1] || '').split(',').map((x) => x.trim().toLowerCase()).filter(Boolean).map((x) => (x === 'default' ? '' : x));
    args.splice(i, 2);
  }
}
const quiet = args.includes('-q');
const json = args.includes('--json');
const q = args.filter((a) => !a.startsWith('-')).join(' ').toLowerCase();

try {
  const list = (await listSecrets())
    .map((s) => ({ name: s.name, scope: s.scope || 'default', category: s.category || '', note: s.note || '' }))
    .filter((s) => !only || only.includes(s.scope === 'default' ? '' : s.scope))
    .filter((s) => !q || `${s.name} ${s.scope} ${s.category} ${s.note}`.toLowerCase().includes(q));
  if (json) process.stdout.write(JSON.stringify(list, null, 2) + '\n');
  else if (quiet) for (const s of list) process.stdout.write(s.name + '\n');
  else if (!list.length) process.stderr.write(q ? `sm-ls: no secret matches "${q}"\n` : 'sm-ls: no secrets yet\n');
  else {
    const sw = Math.max(5, ...list.map((s) => s.scope.length));
    const w = Math.max(4, ...list.map((s) => s.name.length));
    const c = Math.max(8, ...list.map((s) => s.category.length));
    process.stdout.write(`${'SCOPE'.padEnd(sw)}  ${'NAME'.padEnd(w)}  ${'CATEGORY'.padEnd(c)}  NOTE\n`);
    for (const s of list) process.stdout.write(`${s.scope.padEnd(sw)}  ${s.name.padEnd(w)}  ${(s.category || '-').padEnd(c)}  ${s.note}\n`);
  }
} catch (err) {
  process.stderr.write(`sm-ls: ${err.message}\n`);
  process.exit(1);
}
