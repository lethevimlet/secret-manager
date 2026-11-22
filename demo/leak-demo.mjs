// Runs a set of commands through `sm run` against a throwaway store and checks
// whether each one let a secret reach the output (what an agent would see).
import { execSync, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SM = `node ${path.join(ROOT, 'bin/sm.js')}`;
const SMCTL = path.join(ROOT, 'bin/smctl.js');
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'sm-demo-'));
const SECRETS = { TEST: '1234', API_KEY: 'sk-test-abcdef123456', DB_PASS: 'p@ss"w0rd/x+y z' };

const env = { ...process.env, SM_HOME: HOME, SM_BACKEND: 'file' };
for (const [k, v] of Object.entries(SECRETS)) execFileSync('node', [SMCTL, 'set', k], { input: v, env, stdio: ['pipe', 'ignore', 'ignore'] });
// The agent's own environment has no secret values (here: not even placeholders;
// sm exports them itself).
for (const k of Object.keys(SECRETS)) delete env[k];

const sh = (cmd) => {
  try { return execSync(cmd, { env, shell: '/bin/bash', encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); }
  catch (e) { return (e.stdout || '') + (e.stderr || ''); }
};
const q = (s) => `'${s.replace(/'/g, `'\\''`)}'`;
const run = (inner) => sh(`${SM} -c ${q(inner)}`);

// Each case: what the agent runs, and how an attacker would decode the output.
const cases = [
  ['env dump', () => run('env | grep -E "^(TEST|API_KEY|DB_PASS)="'), (o) => o],
  ['echo $VAR', () => run('echo "$API_KEY"'), (o) => o],
  ['placeholder in command', () => run('echo "key={{secret:API_KEY}}"'), (o) => o],
  ['plain bash, not sm', () => sh('echo "[$API_KEY]"'), (o) => o],
  ['base64', () => run('printf %s "$API_KEY" | base64'), (o) => b64(o)],
  ['base64 with prefix (basic auth)', () => run('printf "user:%s" "$API_KEY" | base64'), (o) => b64(o)],
  ['hex', () => run('node -e "console.log(Buffer.from(process.env.DB_PASS).toString(\'hex\'))"'), (o) => hex(o)],
  ['url-encoded', () => run('node -e "console.log(encodeURIComponent(process.env.DB_PASS))"'), (o) => safe(decodeURIComponent, o)],
  ['json', () => run('node -e "console.log(JSON.stringify({p:process.env.DB_PASS}))"'), (o) => safe((x) => JSON.parse(x).p, o)],
  ['stack trace / error message', () => run('node -e "throw new Error(\'auth failed for \' + process.env.API_KEY)"'), (o) => o],
  ['split write, 50 ms gap', () => run('node -e "const k=process.env.API_KEY;process.stdout.write(k.slice(0,8));setTimeout(()=>console.log(k.slice(8)),50)"'), (o) => o],
  ['split write, 500 ms gap', () => run('node -e "const k=process.env.API_KEY;process.stdout.write(k.slice(0,8));setTimeout(()=>console.log(k.slice(8)),500)"'), (o) => o],
  ['rev', () => run('echo "$API_KEY" | rev'), (o) => o.split('').reverse().join('')],
  ['spaced letters', () => run('echo "$API_KEY" | sed "s/./& /g"'), (o) => o.replace(/ /g, '')],
  ['one char per command', () => [...SECRETS.API_KEY].map((_, i) => run(`printf %s "\${API_KEY:${i}:1}"`)).join(''), (o) => o],
  ['yes/no oracle', () => oracle(), (o) => o],
  ['write file, read without sm', () => (run('echo "$API_KEY" > /tmp/sm-demo-leak'), sh('cat /tmp/sm-demo-leak; rm -f /tmp/sm-demo-leak')), (o) => o],
  ['read the store file directly', () => sh(`cat ${HOME}/secrets.json`), (o) => o],
];

// Guess TEST digit by digit: output is only "y"/"n", nothing to redact.
function oracle() {
  let found = '';
  for (let i = 0; i < 4; i++) {
    for (const d of '0123456789') {
      if (run(`[ "\${TEST:${i}:1}" = ${d} ] && echo y || echo n`).trim() === 'y') { found += d; break; }
    }
  }
  return found;
}

const b64 = (o) => safe((x) => Buffer.from(x.trim(), 'base64').toString('utf8'), o);
const hex = (o) => safe((x) => Buffer.from(x.trim(), 'hex').toString('utf8'), o);
function safe(fn, o) { try { return fn(o.trim()); } catch { return ''; } }

const leaked = (text) => Object.entries(SECRETS).filter(([, v]) => text.includes(v)).map(([k]) => k);
// Any 8+ character piece of a secret in the output (e.g. a released prefix).
const partial = (text) => Object.entries(SECRETS).filter(([, v]) => v.length > 8 && [...Array(v.length - 7).keys()].some((i) => text.includes(v.slice(i, i + 8)))).map(([k]) => k);

console.log(`store: ${HOME} (secrets: ${Object.keys(SECRETS).join(', ')})\n`);
console.log('RESULT   CASE                              OUTPUT THE AGENT SEES');
console.log('-------  --------------------------------  ---------------------');
let caught = 0;
for (const [name, fn, decode] of cases) {
  const out = fn();
  const hits = [...new Set([...leaked(out), ...leaked(decode(out))])];
  const parts = hits.length ? [] : partial(out);
  if (!hits.length && !parts.length) caught++;
  const label = hits.length ? 'LEAKED ' : parts.length ? 'PARTIAL' : 'caught ';
  const shown = out.trim().replace(/\s*\n\s*/g, ' | ').slice(0, 70);
  const who = [...hits, ...parts];
  console.log(`${label}  ${name.padEnd(32)}  ${shown}${who.length ? `   (${who.join(', ')})` : ''}`);
}
console.log(`\n${caught}/${cases.length} caught.\n\nLast audit entry (placeholders only, never values):`);
console.log(fs.readFileSync(path.join(HOME, 'audit.log'), 'utf8').trim().split('\n').pop());
fs.rmSync(HOME, { recursive: true, force: true });
