// Scopes: separate sets of secrets; `sm -s work,org` gets only those.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SecretStore, cleanScope, keyOf, splitKey, validKey } from '../server/store.js';
import { createApp, AuditLog } from '../server/app.js';
import { loadTokens } from '../server/index.js';
import { splitScopeArgs, parseScopeList } from '../src/shell.js';
import { Vault } from '../server/vault.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'sm-scope-test-'));
let server, base, tokens, store, audit;

before(async () => {
  tokens = loadTokens(DIR).tokens;
  store = new SecretStore(DIR);
  audit = new AuditLog(path.join(DIR, 'audit.log'));
  const app = createApp({ store, tokens, audit });
  await new Promise((r) => (server = app.listen(0, '127.0.0.1', r)));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => {
  server.close();
  fs.rmSync(DIR, { recursive: true, force: true });
});

const call = (p, { token = tokens.admin, method = 'GET', body } = {}) =>
  fetch(base + '/v1' + p, { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: body && JSON.stringify(body) });

function cli(bin, args, { input, admin = false, env: extra = {} } = {}) {
  const env = { ...process.env, SM_CONFIG: path.join(DIR, 'nocfg.json'), SM_SERVER: base, SM_TOKEN: tokens.client, SM_AUDIT: '1', ...extra };
  delete env.SM_BACKEND;
  for (const k of ['GH_TOKEN', 'ONLY_WORK', 'ONLY_DEFAULT', 'ORG_KEY', 'SM_SCOPES']) if (!(k in extra)) delete env[k];
  if (admin) env.SM_ADMIN_TOKEN = tokens.admin;
  return new Promise((resolve) => {
    const p = spawn('node', [path.join(ROOT, 'bin', bin), ...args], { env });
    let stdout = '', stderr = '';
    p.stdout.on('data', (d) => (stdout += d));
    p.stderr.on('data', (d) => (stderr += d));
    p.on('close', (status) => resolve({ status, stdout, stderr }));
    p.stdin.end(input ?? '');
  });
}

test('scope names and keys', () => {
  assert.equal(cleanScope(undefined), '');
  assert.equal(cleanScope(' Default '), '');
  assert.equal(cleanScope('Work'), 'work');
  assert.throws(() => cleanScope('no/slash'), /invalid scope/);
  assert.throws(() => cleanScope('-x'), /invalid scope/);
  assert.equal(keyOf('A', ''), 'A');
  assert.equal(keyOf('A', 'work'), 'work/A');
  assert.deepEqual(splitKey('work/A'), { scope: 'work', name: 'A' });
  assert.deepEqual(splitKey('A'), { scope: '', name: 'A' });
  assert.ok(validKey('work/A') && validKey('A') && !validKey('Work/A') && !validKey('w/1A'));
  assert.deepEqual(parseScopeList('work, Org,work'), ['work', 'org']);
  assert.deepEqual(splitScopeArgs(['-s', 'work,org', '-c', 'x']), { scopes: ['work', 'org'], given: true, rest: ['-c', 'x'] });
  assert.deepEqual(splitScopeArgs(['--scope=a', '-s', 'b', 'script.sh']).scopes, ['a', 'b']);
  // bash's own -s (read stdin) still works when it isn't followed by a scope list.
  assert.deepEqual(splitScopeArgs(['-s', '--', 'x']), { scopes: [], given: false, rest: ['-s', '--', 'x'] });
  assert.deepEqual(splitScopeArgs(['-c', 'x', '-s', 'y']).given, false);
});

test('the same name in two scopes; list, reveal, edit, delete by scope', async () => {
  assert.equal((await call('/secrets/GH_TOKEN', { method: 'PUT', body: { value: 'default-gh-111' } })).status, 201);
  assert.equal((await call('/secrets/GH_TOKEN?scope=work', { method: 'PUT', body: { value: 'work-gh-222', category: 'GitHub' } })).status, 201);
  assert.equal((await call('/secrets/ONLY_WORK?scope=Work', { method: 'PUT', body: { value: 'only-work-333' } })).status, 201);
  assert.equal((await call('/secrets/ORG_KEY?scope=org', { method: 'PUT', body: { value: 'org-key-444' } })).status, 201);
  assert.equal((await call('/secrets/ONLY_DEFAULT', { method: 'PUT', body: { value: 'only-default-555' } })).status, 201);
  assert.equal((await call('/secrets/X?scope=bad/scope', { method: 'PUT', body: { value: 'abcdefgh' } })).status, 400);

  const list = await call('/secrets').then((r) => r.json());
  assert.deepEqual(list.scopes, ['org', 'work']);
  assert.deepEqual(list.secrets.filter((s) => s.name === 'GH_TOKEN').map((s) => s.scope).sort(), ['', 'work']);
  assert.ok(!JSON.stringify(list).includes('gh-'));

  assert.equal((await call('/secrets/GH_TOKEN/reveal?scope=work', { method: 'POST' }).then((r) => r.json())).value, 'work-gh-222');
  assert.equal((await call('/secrets/GH_TOKEN/reveal', { method: 'POST' }).then((r) => r.json())).value, 'default-gh-111');
  assert.equal((await call('/secrets/ONLY_WORK/reveal', { method: 'POST' })).status, 404);

  // create-only POST respects the scope
  assert.equal((await call('/secrets', { token: tokens.client, method: 'POST', body: { name: 'GH_TOKEN', value: 'xxxxxxxxx', scope: 'work' } })).status, 409);
  assert.equal((await call('/secrets', { token: tokens.client, method: 'POST', body: { name: 'TMP', value: 'tmp-value-1', scope: 'work' } })).status, 201);
  assert.equal((await call('/secrets/TMP?scope=work', { method: 'DELETE' })).status, 204);
  assert.equal((await call('/secrets/TMP?scope=work', { method: 'DELETE' })).status, 404);
  assert.ok(audit.tail(50).entries.some((e) => e.type === 'secret.delete' && e.name === 'TMP' && e.scope === 'work'));
});

test('moving a secret between scopes keeps its value; a taken name is refused', async () => {
  assert.equal((await call('/secrets/MOVE_ME', { method: 'PUT', body: { value: 'move-me-value', note: 'n1' } })).status, 201);
  assert.equal((await call('/secrets/MOVE_ME', { method: 'PATCH', body: { to: 'org' } })).status, 200);
  assert.equal((await call('/secrets/MOVE_ME/reveal?scope=org', { method: 'POST' }).then((r) => r.json())).value, 'move-me-value');
  assert.equal(store.list().find((s) => s.name === 'MOVE_ME').note, 'n1');
  assert.ok(store.tombstones.MOVE_ME, 'the old key is a tombstone (for sync)');
  assert.equal((await call('/secrets/GH_TOKEN', { method: 'PATCH', body: { to: 'work' } })).status, 409);
  assert.ok(audit.tail(50).entries.some((e) => e.type === 'secret.move' && e.name === 'MOVE_ME' && e.from === '' && e.to === 'org'));
  assert.equal((await call('/secrets/MOVE_ME?scope=org', { method: 'DELETE' })).status, 204);
});

test('/resolve: default only without scopes; later scope wins; empty scopes reported', async () => {
  const d = await call('/resolve', { token: tokens.client, method: 'POST', body: {} }).then((r) => r.json());
  assert.deepEqual(Object.keys(d.secrets).sort(), ['GH_TOKEN', 'ONLY_DEFAULT']);
  assert.equal(d.secrets.GH_TOKEN, 'default-gh-111');
  const w = await call('/resolve', { token: tokens.client, method: 'POST', body: { scopes: ['work'] } }).then((r) => r.json());
  assert.deepEqual(Object.keys(w.secrets).sort(), ['GH_TOKEN', 'ONLY_WORK']);
  assert.equal(w.secrets.GH_TOKEN, 'work-gh-222');
  const both = await call('/resolve', { token: tokens.client, method: 'POST', body: { scopes: ['default', 'work', 'org', 'nope'] } }).then((r) => r.json());
  assert.deepEqual(Object.keys(both.secrets).sort(), ['GH_TOKEN', 'ONLY_DEFAULT', 'ONLY_WORK', 'ORG_KEY']);
  assert.equal(both.secrets.GH_TOKEN, 'work-gh-222');
  assert.deepEqual(both.overridden, [{ name: 'GH_TOKEN', scope: 'default', by: 'work' }]);
  assert.deepEqual(both.empty, ['nope']);
  assert.equal((await call('/resolve', { token: tokens.client, method: 'POST', body: { scopes: 'work' } })).status, 400);
});

test('sm -s: only the given scopes reach the command; output redacted; audited', async () => {
  const plain = await cli('sm.js', ['-c', 'echo "[${GH_TOKEN}] [${ONLY_WORK:-unset}] [${ONLY_DEFAULT:-unset}]"']);
  assert.equal(plain.stdout, '[[BLOCKED:GH_TOKEN]] [unset] [[BLOCKED:ONLY_DEFAULT]]\n');
  const work = await cli('sm.js', ['-s', 'work', '-c', 'printf %s "$GH_TOKEN" | wc -c; echo "[${ONLY_DEFAULT:-unset}] [${SM_SCOPES}]"; [ "$GH_TOKEN" = work-gh-222 ] && echo ok']);
  assert.equal(work.stdout, `${'work-gh-222'.length}\n[unset] [work]\nok\n`, work.stderr);
  const multi = await cli('sm.js', ['-s', 'work,org', '-c', '[ -n "$ORG_KEY" ] && [ -n "$ONLY_WORK" ] && echo both']);
  assert.equal(multi.stdout, 'both\n');
  const warn = await cli('sm.js', ['-s', 'default,work', '-s', 'missing', '-c', 'true']);
  assert.match(warn.stderr, /GH_TOKEN is in scopes default and work; using work's/);
  assert.match(warn.stderr, /scope missing has no secrets/);
  // a nested sm without -s keeps the scopes it runs in
  const nested = await cli('sm.js', ['-s', 'work', '-c', `node ${JSON.stringify(path.join(ROOT, 'bin/sm.js'))} -c '[ "$GH_TOKEN" = work-gh-222 ] && echo nested-ok'`]);
  assert.equal(nested.stdout, 'nested-ok\n', nested.stderr);
  const bad = await cli('sm.js', ['-s', 'Bad/Scope', '-c', 'true']);
  assert.equal(bad.status, 2);
  assert.ok(audit.tail(100).entries.some((e) => e.type === 'command' && e.scopes?.join() === 'work,org'));
});

test('CLIs: sm-add/sm-ls/smctl take --scope; smctl move and scopes', async () => {
  let r = await cli('sm-add.js', ['NEW_WORK', '--generate', '--scope', 'work']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /in scope work.*sm -s work/);
  r = await cli('sm-add.js', ['NEW_WORK', '--generate', '--scope', 'work']);
  assert.equal(r.status, 3);
  r = await cli('sm-ls.js', ['-s', 'work', '-q']);
  assert.deepEqual(r.stdout.trim().split('\n'), ['GH_TOKEN', 'NEW_WORK', 'ONLY_WORK']);
  r = await cli('sm-ls.js', []);
  assert.match(r.stdout, /^SCOPE\s+NAME/);
  assert.match(r.stdout, /\nwork\s+GH_TOKEN/);
  r = await cli('smctl.js', ['set', 'CLI_ORG', '--scope', 'org'], { input: 'cli-org-value', admin: true });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(store.reveal('CLI_ORG', 'org'), 'cli-org-value');
  r = await cli('smctl.js', ['move', 'CLI_ORG', '--scope', 'org', '--to', 'default'], { admin: true });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(store.reveal('CLI_ORG'), 'cli-org-value');
  r = await cli('smctl.js', ['scopes'], { admin: true });
  assert.match(r.stdout, /^default\s+\d+\norg\s+1\nwork\s+3\n$/);
  r = await cli('smctl.js', ['rm', 'NEW_WORK'], { admin: true });
  assert.notEqual(r.status, 0); // not in the default scope
  r = await cli('smctl.js', ['rm', 'NEW_WORK', '-s', 'work'], { admin: true });
  assert.equal(r.status, 0, r.stderr);
  r = await cli('smctl.js', ['rm', 'CLI_ORG'], { admin: true });
  assert.equal(r.status, 0, r.stderr);
});

test('deleting a scope deletes its secrets and needs the name typed', async () => {
  for (const [n, v] of [['RM_A', 'rm-a-value-1'], ['RM_B', 'rm-b-value-2']]) {
    assert.equal((await call(`/secrets/${n}?scope=gone`, { method: 'PUT', body: { value: v } })).status, 201);
  }
  assert.equal((await call('/secrets/RM_A', { method: 'PUT', body: { value: 'default-rm-a' } })).status, 201);
  const del = (scope, body) => call(`/scopes/${scope}/delete`, { method: 'POST', body });
  assert.equal((await call('/scopes/gone/delete', { token: tokens.client, method: 'POST', body: { confirm: 'gone' } })).status, 403);
  assert.equal((await del('default', { confirm: 'default' })).status, 400);
  assert.equal((await del('gone', {})).status, 400);
  assert.equal((await del('gone', { confirm: 'gone-x' })).status, 400);
  assert.equal(store.list().filter((s) => s.scope === 'gone').length, 2, 'nothing deleted yet');

  let r = await cli('smctl.js', ['scopes', 'rm', 'gone'], { admin: true });
  assert.notEqual(r.status, 0); // no terminal and no --confirm
  assert.match(r.stderr, /--confirm gone/);
  r = await cli('smctl.js', ['scopes', 'rm', 'gone', '--confirm', 'gone'], { admin: true });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(store.has('RM_A', 'gone') || store.has('RM_B', 'gone'), false);
  assert.ok(!store.scopes().includes('gone'));
  assert.equal(store.reveal('RM_A'), 'default-rm-a', 'the same name in Default is untouched');
  assert.ok(store.tombstones['gone/RM_A'], 'deletions are tombstoned for sync');
  assert.ok(audit.tail(20).entries.some((e) => e.type === 'scope.delete' && e.scope === 'gone' && e.names.join() === 'RM_A,RM_B'));
  assert.equal((await call('/secrets/RM_A', { method: 'DELETE' })).status, 204);
});

test('the local file store has only the default scope', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sm-scope-file-'));
  try {
    const env = { ...process.env, SM_HOME: home, SM_BACKEND: 'file', SM_AUDIT: '0' };
    const out = execFileSync('node', [path.join(ROOT, 'bin/sm.js'), '-s', 'work', '-c', 'echo "[${X:-none}]"'], { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    assert.equal(out, '[none]\n');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('the interactive prompt tag shows the scopes', () => {
  const rc = path.join(ROOT, 'src/sm-rc.bash');
  const env = { ...process.env };
  delete env.SM_PROMPT;
  const run = (scopes) => execFileSync('bash', ['--norc', '-c', `. ${JSON.stringify(rc)}; printf %s "$PS1"`], { env: { ...env, SM_SCOPES: scopes }, encoding: 'utf8' });
  const RED = '\\[\x1b[1;31m\\]';
  const OFF = '\\[\x1b[0m\\] ';
  assert.ok(run('work,org').startsWith(`${RED}sm[work,org]${OFF}`));
  assert.ok(run('').startsWith(`${RED}sm${OFF}`));
});

test('scoped secrets sync through the vault; Default keys stay compatible', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sm-scope-vault-'));
  try {
    const repo = path.join(root, 'v.git');
    execFileSync('git', ['init', '--quiet', '--bare', '-b', 'main', repo]);
    const mk = (n) => {
      const dir = path.join(root, n);
      const st = new SecretStore(dir, { device: n });
      return { st, vault: new Vault({ dir, store: st }) };
    };
    const a = mk('alpha');
    a.st.set('TOKEN', 'default-token-1');
    a.st.set('TOKEN', 'work-token-2', '', '', 'work');
    const keyFile = await a.vault.init({ repo, password: 'correct horse battery' });
    const b = mk('beta');
    await b.vault.join({ keyFile, password: 'correct horse battery' });
    assert.equal(b.st.reveal('TOKEN'), 'default-token-1');
    assert.equal(b.st.reveal('TOKEN', 'work'), 'work-token-2');
    await new Promise((r) => setTimeout(r, 5));
    b.st.update('TOKEN', { to: 'org' }, 'work');
    await b.vault.syncNow();
    await a.vault.syncNow();
    assert.equal(a.st.has('TOKEN', 'work'), false);
    assert.equal(a.st.reveal('TOKEN', 'org'), 'work-token-2');
    const history = execFileSync('git', ['--git-dir', repo, 'log', '-p', '--all']).toString();
    for (const leak of ['TOKEN', 'work', 'org', 'token-']) assert.ok(!history.includes(leak), leak);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
