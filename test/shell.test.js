import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { rewriteCommand } from '../src/rewrite.js';
import { parseArgs } from '../src/shell.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SM = path.join(ROOT, 'bin/sm.js');
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'sm-test-'));
const VALUE = `it's "q" $HOME \\ \`x\``; // quotes, $, backslash, backtick
const env = { ...process.env, SM_HOME: HOME, SM_BACKEND: 'file' };
delete env.API_KEY;

before(() => {
  execFileSync('node', [path.join(ROOT, 'bin/smctl.js'), 'set', 'API_KEY'], { input: 'sk-test-abcdef123456', env, stdio: ['pipe', 'ignore', 'ignore'] });
  execFileSync('node', [path.join(ROOT, 'bin/smctl.js'), 'set', 'WEIRD'], { input: VALUE, env, stdio: ['pipe', 'ignore', 'ignore'] });
});

after(() => fs.rmSync(HOME, { recursive: true, force: true }));

const sm = (args, extraEnv = {}) => spawnSync('node', [SM, ...args], { env: { ...env, SM_AUDIT: '0', ...extraEnv }, encoding: 'utf8' });

// Run bash with the rewritten command and the secret only in __SM_WEIRD, then
// check the value bash sees is exact. Proves quoting is right in each context.
for (const [label, cmd] of [
  ['unquoted', 'printf %s {{secret:WEIRD}}'],
  ['double quotes', 'printf %s "v={{secret:WEIRD}}"'],
  ['single quotes', "printf %s 'v={{secret:WEIRD}}'"],
  ['ansi-c', "printf %s $'v=\\t{{secret:WEIRD}}'"],
  ['after escaped quote', 'printf %s \\"{{secret:WEIRD}}'],
]) {
  test(`rewrite keeps the exact value: ${label}`, () => {
    const rewritten = rewriteCommand(cmd);
    assert.ok(!rewritten.includes('{{secret:'), rewritten);
    const real = execFileSync('bash', ['-c', cmd.replace('{{secret:WEIRD}}', 'MARK')], { encoding: 'utf8' });
    const got = execFileSync('bash', ['-c', rewritten], { env: { ...process.env, __SM_WEIRD: VALUE }, encoding: 'utf8' });
    assert.equal(got, real.replace('MARK', VALUE));
  });
}

test('parseArgs finds the command string in bash-style invocations', () => {
  assert.equal(parseArgs(['-c', 'echo']).commandIndex, 1);
  assert.equal(parseArgs(['-lc', 'echo']).commandIndex, 1);
  assert.equal(parseArgs(['-l', '-c', 'echo']).commandIndex, 2);
  assert.equal(parseArgs(['-o', 'pipefail', '-c', 'echo']).commandIndex, 3);
  assert.equal(parseArgs(['--norc', '-c', 'echo', 'zero', 'one']).commandIndex, 2);
  assert.equal(parseArgs(['script.sh']).commandIndex, -1);
  assert.equal(parseArgs(['script.sh']).operandIndex, 0);
});

test('sm -c: env var and placeholder both resolve, output redacted', () => {
  const r = sm(['-c', 'echo "$API_KEY"; echo {{secret:API_KEY}}; printf %s "$API_KEY" | base64']);
  assert.equal(r.status, 0);
  assert.equal(r.stdout.trim().split('\n').slice(0, 2).join('|'), '[BLOCKED:API_KEY]|[BLOCKED:API_KEY]');
  assert.ok(!r.stdout.includes('sk-test'));
});

test('sm -c: the real value reaches the program', () => {
  const r = sm(['-c', '[ "$API_KEY" = sk-test-abcdef123456 ] && [ {{secret:WEIRD}} = "$WEIRD" ] && echo ok']);
  assert.equal(r.stdout.trim(), 'ok');
});

test('placeholder values in the inherited env are substituted', () => {
  const r = sm(['-c', '[ "$TOKEN" = "Bearer sk-test-abcdef123456" ] && echo ok'], { TOKEN: 'Bearer {{secret:API_KEY}}' });
  assert.equal(r.stdout.trim(), 'ok');
});

test('stderr is redacted and the exit code is preserved', () => {
  const r = sm(['-c', 'echo "$API_KEY" >&2; exit 7']);
  assert.equal(r.status, 7);
  assert.equal(r.stderr.trim(), '[BLOCKED:API_KEY]');
});

test('script file with arguments', () => {
  const f = path.join(HOME, 's.sh');
  fs.writeFileSync(f, 'echo "$1 $API_KEY"\n');
  const r = sm([f, 'hello']);
  assert.equal(r.stdout.trim(), 'hello [BLOCKED:API_KEY]');
});

test('commands piped on stdin', () => {
  const r = spawnSync('node', [SM], { env: { ...env, SM_AUDIT: '0' }, input: 'echo "$API_KEY"\n', encoding: 'utf8' });
  assert.equal(r.stdout.trim(), '[BLOCKED:API_KEY]');
});

test('unknown placeholder fails before running anything', () => {
  const r = sm(['-c', 'touch /tmp/sm-should-not-exist; echo {{secret:NOPE}}']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /unknown secret: NOPE/);
  assert.ok(!fs.existsSync('/tmp/sm-should-not-exist'));
});

test('agent guard: agents started inside sm get no secrets', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sm-agent-'));
  fs.writeFileSync(path.join(dir, 'opencode'), '#!/bin/bash\necho "k=${API_KEY:-none} w=${WEIRD:-none} a=${SM_ACTIVE:-none} t=${TOK:-none}"\n', { mode: 0o755 });
  const r = sm(['-c', 'echo "shell=${#API_KEY}"; opencode; echo {{secret:API_KEY}} >/dev/null; opencode'], { PATH: `${dir}:${process.env.PATH}`, TOK: 'Bearer {{secret:API_KEY}}' });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, 'shell=20\nk=none w=none a=none t=none\nk=none w=none a=none t=none\n');
  assert.match(r.stderr, /starting opencode without secrets/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('git-credential-sm: answers only with the token in the environment of an sm shell', () => {
  const helper = path.join(ROOT, 'bin/git-credential-sm.js');
  const ask = (envExtra) => spawnSync('node', [helper, 'get'], { input: 'protocol=https\nhost=github.com\n\n', encoding: 'utf8', env: { PATH: process.env.PATH, ...envExtra } });
  const outside = ask({});
  assert.equal(outside.stdout, 'quit=1\n');
  assert.match(outside.stderr, /only available inside sm/);
  assert.equal(ask({ SM_ACTIVE: '1' }).stdout, 'quit=1\n'); // faking SM_ACTIVE gets nothing
  assert.equal(ask({ SM_ACTIVE: '1', GITHUB_TOKEN: 'ghp_example_value_123' }).stdout, 'username=x-access-token\npassword=ghp_example_value_123\n');
  const other = spawnSync('node', [helper, 'get'], { input: 'protocol=https\nhost=gitlab.com\n\n', encoding: 'utf8', env: { PATH: process.env.PATH, SM_ACTIVE: '1', GITHUB_TOKEN: 'x' } });
  assert.equal(other.stdout, '');
  // Through sm the password is blocked if anyone prints it.
  const viaSm = sm(['-c', `printf 'protocol=https\\nhost=github.com\\n\\n' | GITHUB_TOKEN="$API_KEY" node ${helper} get`]);
  assert.equal(viaSm.stdout, 'username=x-access-token\npassword=[BLOCKED:API_KEY]\n');
});
