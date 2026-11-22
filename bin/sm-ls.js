#!/usr/bin/env node
// sm-ls: list secret names (never values), for people and agents.
//   sm-ls              name, category, note
//   sm-ls github       only entries whose name, category or note contains "github"
//   sm-ls -q           names only
//   sm-ls --json       machine-readable
import { listSecrets } from '../src/backend.js';

const args = process.argv.slice(2);
if (args.includes('-h') || args.includes('--help')) {
  process.stdout.write('usage: sm-ls [SEARCH] [-q] [--json]\nLists secret names, categories and notes. Never values.\n');
  process.exit(0);
}
const quiet = args.includes('-q');
const json = args.includes('--json');
const q = args.filter((a) => !a.startsWith('-')).join(' ').toLowerCase();

try {
  const list = (await listSecrets())
    .map((s) => ({ name: s.name, category: s.category || '', note: s.note || '' }))
    .filter((s) => !q || `${s.name} ${s.category} ${s.note}`.toLowerCase().includes(q));
  if (json) process.stdout.write(JSON.stringify(list, null, 2) + '\n');
  else if (quiet) for (const s of list) process.stdout.write(s.name + '\n');
  else if (!list.length) process.stderr.write(q ? `sm-ls: no secret matches "${q}"\n` : 'sm-ls: no secrets yet\n');
  else {
    const w = Math.max(4, ...list.map((s) => s.name.length));
    const c = Math.max(8, ...list.map((s) => s.category.length));
    process.stdout.write(`${'NAME'.padEnd(w)}  ${'CATEGORY'.padEnd(c)}  NOTE\n`);
    for (const s of list) process.stdout.write(`${s.name.padEnd(w)}  ${(s.category || '-').padEnd(c)}  ${s.note}\n`);
  }
} catch (err) {
  process.stderr.write(`sm-ls: ${err.message}\n`);
  process.exit(1);
}
