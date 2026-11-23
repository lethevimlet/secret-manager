#!/usr/bin/env node
// sm-add: create a NEW secret without the value ever appearing in a
// terminal, a command line or an agent's context. Never replaces an existing one.
//
//   sm-add NAME --generate [LENGTH, default 12] [--charset alnum|hex|base64url|symbols]
//   some-command-that-prints-a-token | sm-add NAME
//   sm-add NAME            (interactive terminal: asks for the value, hidden)
//   options: --scope NAME (default: the default scope)  --category NAME  --note TEXT
//            --if-missing (exit 0 if it exists)
import { NAME_RE } from '../src/store.js';
import { createSecret } from '../src/backend.js';
import { generateValue as gen } from '../src/generate.js';

const USAGE = `usage: sm-add NAME --generate [LENGTH] [--charset alnum|hex|base64url|symbols]
       COMMAND | sm-add NAME
       options: --scope NAME  --category NAME  --note TEXT  --if-missing
The value is never taken from the command line. Existing secrets are never replaced.
`;
const args = process.argv.slice(2);
const fail = (msg, code = 2) => {
  process.stderr.write(`sm-add: ${msg}\n`);
  process.exit(code);
};
const take = (flag) => {
  const i = args.indexOf(flag);
  if (i === -1) return undefined;
  const v = args[i + 1];
  if (v === undefined || v.startsWith('--')) fail(`${flag} needs a value`);
  args.splice(i, 2);
  return v;
};
if (args.includes('-h') || args.includes('--help')) {
  process.stdout.write(USAGE);
  process.exit(0);
}

const scope = take('--scope') ?? take('-s');
const category = take('--category');
const note = take('--note');
const charsetName = take('--charset') || 'alnum';
const ifMissing = args.includes('--if-missing') && args.splice(args.indexOf('--if-missing'), 1);
let generate = null;
const g = args.indexOf('--generate');
if (g !== -1) {
  const n = args[g + 1];
  if (n !== undefined && /^\d+$/.test(n)) {
    generate = Number(n);
    args.splice(g, 2);
  } else {
    generate = 12;
    args.splice(g, 1);
  }
}
const [name, ...extra] = args;
if (!name) fail(USAGE.trimEnd());
if (extra.length) fail('the value is never taken from the command line: use --generate, or pipe it in (COMMAND | sm-add NAME)');
if (!NAME_RE.test(name)) fail('invalid name: letters, digits and _, not starting with a digit');

function generateValue(len, set) {
  try {
    return gen(len, set);
  } catch (err) {
    fail(err.message);
  }
}

async function readValue() {
  if (process.stdin.isTTY) {
    process.stderr.write(`value for ${name} (hidden): `);
    process.stdin.setRawMode(true);
    let v = '';
    for await (const chunk of process.stdin) {
      for (const ch of chunk.toString('utf8')) {
        if (ch === '\r' || ch === '\n') {
          process.stdin.setRawMode(false);
          process.stderr.write('\n');
          return v;
        }
        if (ch === '\u0003') process.exit(130);
        if (ch === '\u007f') v = v.slice(0, -1);
        else v += ch;
      }
    }
    return v;
  }
  let data = '';
  for await (const chunk of process.stdin) data += chunk;
  return data.replace(/\r?\n$/, '');
}

const value = generate !== null ? generateValue(generate, charsetName) : await readValue();
if (!value) fail(generate === null && !process.stdin.isTTY ? 'nothing on stdin: pipe the value in, or use --generate' : 'empty value');

try {
  await createSecret(name, value, note, category, scope);
  const how = generate !== null ? `generated, ${value.length} chars` : `${value.length} chars from stdin`;
  const inScope = scope && scope.toLowerCase() !== 'default' ? ` in scope ${scope.toLowerCase()}` : '';
  process.stderr.write(`sm-add: stored ${name}${inScope} (${how}). Use it as $${name} inside sm${inScope ? ` -s ${scope.toLowerCase()}` : ''}.\n`);
} catch (err) {
  if (err.exists) {
    if (ifMissing) {
      process.stderr.write(`sm-add: ${name} already exists, left unchanged\n`);
      process.exit(0);
    }
    fail(`${name} already exists${scope ? ` in scope ${scope}` : ''} and was not changed (only the user can replace it, in the GUI)`, 3);
  }
  fail(err.message, 1);
}
