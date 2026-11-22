#!/usr/bin/env node
// sm-add: create a NEW secret without the value ever appearing in a
// terminal, a command line or an agent's context. Never replaces an existing one.
//
//   sm-add NAME --generate [LENGTH] [--charset alnum|hex|base64url|symbols]
//   some-command-that-prints-a-token | sm-add NAME
//   sm-add NAME            (interactive terminal: asks for the value, hidden)
//   options: --category NAME  --note TEXT  --if-missing (exit 0 if it exists)
import crypto from 'node:crypto';
import { NAME_RE } from '../src/store.js';
import { createSecret } from '../src/backend.js';

const USAGE = `usage: sm-add NAME --generate [LENGTH] [--charset alnum|hex|base64url|symbols]
       COMMAND | sm-add NAME
       options: --category NAME  --note TEXT  --if-missing
The value is never taken from the command line. Existing secrets are never replaced.
`;
const CHARSETS = {
  alnum: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
  hex: '0123456789abcdef',
  base64url: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
  symbols: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#%+-.:=?@^_~',
};

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
    generate = 32;
    args.splice(g, 1);
  }
}
const [name, ...extra] = args;
if (!name) fail(USAGE.trimEnd());
if (extra.length) fail('the value is never taken from the command line: use --generate, or pipe it in (COMMAND | sm-add NAME)');
if (!NAME_RE.test(name)) fail('invalid name: letters, digits and _, not starting with a digit');

function generateValue(len, set) {
  const chars = CHARSETS[set];
  if (!chars) fail(`unknown charset ${set} (alnum, hex, base64url, symbols)`);
  if (len < 8 || len > 4096) fail('length must be between 8 and 4096');
  // Rejection sampling: no modulo bias.
  const out = [];
  const limit = 256 - (256 % chars.length);
  while (out.length < len) {
    for (const b of crypto.randomBytes(len * 2)) {
      if (b < limit && out.length < len) out.push(chars[b % chars.length]);
    }
  }
  return out.join('');
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
  await createSecret(name, value, note, category);
  const how = generate !== null ? `generated, ${value.length} chars` : `${value.length} chars from stdin`;
  process.stderr.write(`sm-add: stored ${name} (${how}). Use it as $${name} inside sm.\n`);
} catch (err) {
  if (err.exists) {
    if (ifMissing) {
      process.stderr.write(`sm-add: ${name} already exists, left unchanged\n`);
      process.exit(0);
    }
    fail(`${name} already exists and was not changed (only the user can replace it, in the GUI)`, 3);
  }
  fail(err.message, 1);
}
