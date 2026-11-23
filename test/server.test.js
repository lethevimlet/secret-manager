import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SecretStore } from '../server/store.js';
import { createApp, AuditLog } from '../server/app.js';
import { loadTokens } from '../server/index.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'sm-server-test-'));
let server, base, tokens;

before(async () => {
  tokens = loadTokens(DIR).tokens;
  const app = createApp({ store: new SecretStore(DIR), tokens, audit: new AuditLog(path.join(DIR, 'audit.log')) });
  await new Promise((r) => (server = app.listen(0, '127.0.0.1', r)));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => {
  server.close();
  fs.rmSync(DIR, { recursive: true, force: true });
});

const call = (p, { token = tokens.admin, method = 'GET', body } = {}) =>
  fetch(base + '/v1' + p, { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: body && JSON.stringify(body) });

// Run sm/smctl as a separate process, like the agent would. Must be async:
// a sync spawn would block the event loop that serves the in-process server.
function cli(bin, args, { input, admin = false } = {}) {
  const env = { ...process.env, SM_CONFIG: path.join(DIR, 'nocfg.json'), SM_SERVER: base, SM_TOKEN: tokens.client, SM_AUDIT: '1' };
  delete env.SM_BACKEND;
  delete env.API_KEY;
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

test('auth: no token, wrong token, client cannot manage', async () => {
  assert.equal((await fetch(base + '/v1/secrets')).status, 401);
  assert.equal((await call('/secrets', { token: 'nope' })).status, 401);
  assert.equal((await call('/secrets/X', { token: tokens.client, method: 'PUT', body: { value: 'abcdefgh' } })).status, 403);
  assert.equal((await call('/audit', { token: tokens.client })).status, 403);
  assert.equal((await call('/whoami', { token: tokens.client }).then((r) => r.json())).scope, 'client');
});

test('admin creates, lists (no values), updates, deletes', async () => {
  assert.equal((await call('/secrets/DEMO', { method: 'PUT', body: { value: 'value-one-123', note: 'test' } })).status, 201);
  assert.equal((await call('/secrets/DEMO', { method: 'PUT', body: { value: 'value-two-456' } })).status, 200);
  const list = await call('/secrets').then((r) => r.json());
  assert.deepEqual(list.secrets.map((s) => [s.name, s.note]), [['DEMO', 'test']]);
  assert.ok(!JSON.stringify(list).includes('value-two'));
  assert.equal((await call('/secrets/DEMO', { method: 'DELETE' })).status, 204);
  assert.equal((await call('/secrets/DEMO', { method: 'DELETE' })).status, 404);
});

test('invalid names and values are rejected', async () => {
  assert.equal((await call('/secrets/1BAD', { method: 'PUT', body: { value: 'x' } })).status, 400);
  assert.equal((await call('/secrets/OK', { method: 'PUT', body: { value: '' } })).status, 400);
  assert.equal((await call('/secrets/OK', { method: 'PUT', body: { value: 42 } })).status, 400);
});

test('stored data is encrypted on disk', async () => {
  await call('/secrets/DISK', { method: 'PUT', body: { value: 'plaintext-marker-xyz' } });
  assert.ok(!fs.readFileSync(path.join(DIR, 'secrets.json'), 'utf8').includes('plaintext-marker'));
  const again = new SecretStore(DIR);
  assert.equal(again.resolveAll().DISK, 'plaintext-marker-xyz');
  await call('/secrets/DISK', { method: 'DELETE' });
});

test('smctl set via server, sm resolves from server, audit recorded', async () => {
  const set = await cli('smctl.js', ['set', 'API_KEY', '--note', 'from test'], { input: 'sk-test-abcdef123456', admin: true });
  assert.equal(set.status, 0, set.stderr);
  const r = await cli('sm.js', ['-c', 'echo "$API_KEY"; [ ${#API_KEY} = 20 ] && echo real-value-seen']);
  assert.equal(r.stdout, '[BLOCKED:API_KEY]\nreal-value-seen\n');
  const { entries } = await call('/audit').then((x) => x.json());
  const cmd = entries.find((e) => e.type === 'command');
  assert.equal(cmd.command, 'echo "$API_KEY"; [ ${#API_KEY} = 20 ] && echo real-value-seen');
  assert.deepEqual(cmd.redactions, { API_KEY: 1 });
  assert.ok(entries.some((e) => e.type === 'resolve' && e.by === 'client'));
  assert.ok(!JSON.stringify(entries).includes('sk-test-abcdef'));
});

test('smctl with only the client token cannot write', async () => {
  const r = await cli('smctl.js', ['set', 'NOPE'], { input: 'abcdefgh123' });
  assert.notEqual(r.status, 0);
});

test('sm still runs commands when the server is down', () => {
  const env = { ...process.env, SM_CONFIG: path.join(DIR, 'nocfg.json'), SM_SERVER: 'http://127.0.0.1:9', SM_TOKEN: 'x' };
  delete env.SM_BACKEND;
  const r = spawnSync('node', [path.join(ROOT, 'bin/sm.js'), '-c', 'echo still-works'], { env, encoding: 'utf8' });
  assert.equal(r.stdout, 'still-works\n');
  assert.match(r.stderr, /unreachable.*running without secrets/);
});

test('GUI is served with a strict CSP', async () => {
  const res = await fetch(base + '/');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-security-policy'), /default-src 'self'/);
  assert.match(await res.text(), /<title>secret-manager<\/title>/);
});

test('SM_NO_AUTH: manage without a token, values still need one', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sm-noauth-'));
  const t = loadTokens(dir).tokens;
  const app = createApp({ store: new SecretStore(dir), tokens: t, audit: new AuditLog(path.join(dir, 'audit.log')), noAuth: true });
  const srv = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  const u = `http://127.0.0.1:${srv.address().port}/v1`;
  try {
    assert.deepEqual(await fetch(u + '/whoami').then((r) => r.json()), { scope: 'admin', anonymous: true, session: false });
    assert.equal((await fetch(u + '/secrets/OPEN', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ value: 'open-value-123' }) })).status, 201);
    assert.equal((await fetch(u + '/resolve', { method: 'POST' })).status, 401);
    assert.equal((await fetch(u + '/secrets', { headers: { Authorization: 'Bearer wrong' } })).status, 401);
    const vals = await fetch(u + '/resolve', { method: 'POST', headers: { Authorization: `Bearer ${t.client}` } }).then((r) => r.json());
    assert.equal(vals.secrets.OPEN, 'open-value-123');
  } finally {
    srv.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('activity log is pruned by age and count', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sm-audit-'));
  const file = path.join(dir, 'audit.log');
  const old = new Date(Date.now() - 40 * 86400_000).toISOString();
  fs.writeFileSync(file, [...Array(5)].map((_, i) => JSON.stringify({ time: old, type: 'old', i })).join('\n') + '\n');
  const log = new AuditLog(file, { days: 30, max: 3 });
  assert.equal(log.tail(100).total, 0); // all older than 30 days
  for (let i = 0; i < 5; i++) log.add({ type: 'command', i });
  assert.equal(log.prune(), 2);
  const { entries, total } = log.tail(100);
  assert.equal(total, 3);
  assert.deepEqual(entries.map((e) => e.i), [4, 3, 2]);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('categories: set on create, edit without touching the value, listed', async () => {
  assert.equal((await call('/secrets/GH_TOKEN', { method: 'PUT', body: { value: 'gh-value-123456', category: '  GitHub  ' } })).status, 201);
  assert.equal((await call('/secrets/AWS_KEY', { method: 'PUT', body: { value: 'aws-value-123456' } })).status, 201);
  assert.equal((await call('/secrets/AWS_KEY', { method: 'PATCH', body: { category: 'Cloud', note: 'prod' } })).status, 200);
  assert.equal((await call('/secrets/AWS_KEY', { method: 'PATCH', body: {} })).status, 400);
  const data = await call('/secrets').then((r) => r.json());
  const by = Object.fromEntries(data.secrets.map((s) => [s.name, s]));
  assert.equal(by.GH_TOKEN.category, 'GitHub');
  assert.deepEqual([by.AWS_KEY.category, by.AWS_KEY.note], ['Cloud', 'prod']);
  assert.deepEqual(data.categories, ['Cloud', 'GitHub']);
  // Replacing the value keeps the category.
  await call('/secrets/AWS_KEY', { method: 'PUT', body: { value: 'aws-value-new-789' } });
  assert.equal((await call('/secrets').then((r) => r.json())).secrets.find((s) => s.name === 'AWS_KEY').category, 'Cloud');
  const vals = await call('/resolve', { token: tokens.client, method: 'POST' }).then((r) => r.json());
  assert.equal(vals.secrets.AWS_KEY, 'aws-value-new-789');
  await call('/secrets/GH_TOKEN', { method: 'DELETE' });
  await call('/secrets/AWS_KEY', { method: 'DELETE' });
});

test('reveal: admin token only, logged, not counted as a use', async () => {
  await call('/secrets/SHOWME', { method: 'PUT', body: { value: 'show-me-value-42' } });
  const r = await call('/secrets/SHOWME/reveal', { method: 'POST' });
  assert.equal(r.status, 200);
  assert.equal((await r.json()).value, 'show-me-value-42');
  assert.equal((await call('/secrets/SHOWME/reveal', { method: 'POST', token: tokens.client })).status, 401);
  assert.equal((await call('/secrets/NOPE/reveal', { method: 'POST' })).status, 404);
  const s = (await call('/secrets').then((x) => x.json())).secrets.find((x) => x.name === 'SHOWME');
  assert.equal(s.uses, 0);
  const { entries } = await call('/audit').then((x) => x.json());
  assert.ok(entries.some((e) => e.type === 'secret.reveal' && e.name === 'SHOWME'));
  assert.ok(!JSON.stringify(entries).includes('show-me-value'));
  await call('/secrets/SHOWME', { method: 'DELETE' });
});

test('reveal: SM_NO_AUTH does not open it up', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sm-noauth-reveal-'));
  const t = loadTokens(dir).tokens;
  const store = new SecretStore(dir);
  store.set('X', 'hidden-value-1');
  const app = createApp({ store, tokens: t, audit: new AuditLog(path.join(dir, 'audit.log')), noAuth: true });
  const srv = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  const u = `http://127.0.0.1:${srv.address().port}/v1/secrets/X/reveal`;
  try {
    const anon = await fetch(u, { method: 'POST' });
    assert.equal(anon.status, 401);
    assert.equal((await anon.json()).needAdminToken, true);
    assert.equal((await fetch(u, { method: 'POST', headers: { Authorization: `Bearer ${t.admin}` } }).then((r) => r.json())).value, 'hidden-value-1');
  } finally {
    srv.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('sm-add: generate, pipe, refuses argv values and existing names; sm-ls lists names only', async () => {
  const gen = await cli('sm-add.js', ['GEN_ONE', '--generate', '40', '--category', 'T', '--note', 'test']);
  assert.equal(gen.status, 0, gen.stderr);
  const piped = await cli('sm-add.js', ['PIPED_ONE'], { input: 'piped-value-123456\n' });
  assert.equal(piped.status, 0, piped.stderr);
  assert.equal((await cli('sm-add.js', ['ARGV_ONE', 'plain-value-123'])).status, 2);
  assert.equal((await cli('sm-add.js', ['GEN_ONE', '--generate'])).status, 3);
  assert.equal((await cli('sm-add.js', ['GEN_ONE', '--generate', '--if-missing'])).status, 0);
  assert.equal((await cli('sm-add.js', ['EMPTY_ONE'])).status, 2);
  const vals = await call('/resolve', { token: tokens.client, method: 'POST' }).then((r) => r.json());
  assert.match(vals.secrets.GEN_ONE, /^[A-Za-z0-9]{40}$/);
  assert.equal(vals.secrets.PIPED_ONE, 'piped-value-123456');
  assert.ok(!gen.stdout.includes(vals.secrets.GEN_ONE) && !gen.stderr.includes(vals.secrets.GEN_ONE));
  const ls = await cli('sm-ls.js', ['one']);
  assert.match(ls.stdout, /GEN_ONE\s+T\s+test/);
  assert.ok(!ls.stdout.includes('piped-value'));
  const q = await cli('sm-ls.js', ['-q', 'piped']);
  assert.equal(q.stdout, 'PIPED_ONE\n');
  const { entries } = await call('/audit').then((r) => r.json());
  assert.ok(entries.some((e) => e.type === 'secret.create' && e.name === 'PIPED_ONE' && e.by === 'client'));
  await call('/secrets/GEN_ONE', { method: 'DELETE' });
  await call('/secrets/PIPED_ONE', { method: 'DELETE' });
});

test('GUI password: setup code off-loopback, scrypt hash, login, CSRF guard, lockout, reset', async () => {
  const { GuiAuth, COOKIE } = await import('../server/auth.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sm-auth-'));
  const t = loadTokens(dir).tokens;
  const guiAuth = new GuiAuth(dir);
  const app = createApp({ store: new SecretStore(dir), tokens: t, audit: new AuditLog(path.join(dir, 'audit.log')), guiAuth });
  const srv = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  const u = `http://127.0.0.1:${srv.address().port}/v1`;
  const post = (p, body, headers = {}) => fetch(u + p, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-SM-GUI': '1', ...headers }, body: JSON.stringify(body) });
  const cookieOf = (r) => /sm_session=([^;]+)/.exec(r.headers.get('set-cookie') || '')?.[1];
  try {
    assert.deepEqual(await fetch(u + '/auth/status').then((r) => r.json()), { passwordSet: false, loggedIn: false, setupNeedsCode: false, minPassword: 10 });
    assert.equal((await fetch(u + '/secrets')).status, 401);
    assert.equal((await post('/auth/setup', { password: 'short' })).status, 400);
    // Not from loopback: the setup code is required (simulated by checking it directly).
    const code = guiAuth.getSetupCode();
    assert.ok(guiAuth.checkSetupCode(code.toLowerCase()) && !guiAuth.checkSetupCode('WRONG-CODE1'));
    const setup = await post('/auth/setup', { password: 'correct horse battery' });
    assert.equal(setup.status, 201);
    assert.equal((await post('/auth/setup', { password: 'another password!' })).status, 409);
    // Stored only as a scrypt hash.
    const rec = fs.readFileSync(path.join(dir, 'auth.json'), 'utf8');
    assert.ok(!rec.includes('correct horse') && JSON.parse(rec).scheme === 'scrypt');
    assert.equal((fs.statSync(path.join(dir, 'auth.json')).mode & 0o777).toString(8), '600');
    // Session from setup works; changes need the X-SM-GUI header.
    const c1 = cookieOf(setup);
    assert.match(setup.headers.get('set-cookie'), /HttpOnly/i);
    assert.equal((await fetch(u + '/secrets', { headers: { Cookie: `${COOKIE}=${c1}` } })).status, 200);
    assert.equal((await fetch(u + '/secrets/A', { method: 'PUT', headers: { Cookie: `${COOKIE}=${c1}`, 'Content-Type': 'application/json' }, body: '{"value":"abcdefgh12"}' })).status, 403);
    assert.equal((await fetch(u + '/secrets/A', { method: 'PUT', headers: { Cookie: `${COOKIE}=${c1}`, 'Content-Type': 'application/json', 'X-SM-GUI': '1' }, body: '{"value":"abcdefgh12"}' })).status, 201);
    // A session can view values.
    assert.equal((await fetch(u + '/secrets/A/reveal', { method: 'POST', headers: { Cookie: `${COOKIE}=${c1}`, 'X-SM-GUI': '1' } }).then((r) => r.json())).value, 'abcdefgh12');
    // Login, wrong password, lockout after 5.
    assert.equal((await post('/auth/login', { password: 'correct horse battery' })).status, 200);
    for (let i = 0; i < 5; i++) assert.equal((await post('/auth/login', { password: 'nope' })).status, 401);
    assert.equal((await post('/auth/login', { password: 'correct horse battery' })).status, 429);
    guiAuth.failures.clear();
    // Logout ends the session.
    await post('/auth/logout', {}, { Cookie: `${COOKIE}=${c1}` });
    assert.equal((await fetch(u + '/secrets', { headers: { Cookie: `${COOKIE}=${c1}` } })).status, 401);
    // Reset with the admin token (smctl passwd); old password stops working.
    assert.equal((await fetch(u + '/auth/password', { method: 'PUT', headers: { Authorization: `Bearer ${t.admin}`, 'Content-Type': 'application/json' }, body: '{"password":"brand new password"}' })).status, 200);
    assert.equal((await post('/auth/login', { password: 'correct horse battery' })).status, 401);
    assert.equal((await post('/auth/login', { password: 'brand new password' })).status, 200);
    // The client token can't read the setup code or change the password.
    assert.equal((await fetch(u + '/auth/setup-code', { headers: { Authorization: `Bearer ${t.client}` } })).status, 403);
  } finally {
    srv.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('rotate: server-generated values, charset/length, audit without values, smctl rotate', async () => {
  await call('/secrets/ROT', { method: 'PUT', body: { value: 'manual-value-123', category: 'R', note: 'keep me' } });
  const r = await call('/secrets/ROT', { method: 'PUT', body: { generate: { length: 40, charset: 'hex' } } }).then((x) => x.json());
  assert.deepEqual([r.created, r.generated, r.length], [false, true, 40]);
  assert.ok(!JSON.stringify(r).includes('value'));
  let v = (await call('/resolve', { token: tokens.client, method: 'POST' }).then((x) => x.json())).secrets.ROT;
  assert.match(v, /^[0-9a-f]{40}$/);
  const meta = (await call('/secrets').then((x) => x.json())).secrets.find((s) => s.name === 'ROT');
  assert.deepEqual([meta.category, meta.note], ['R', 'keep me']);
  assert.equal((await call('/secrets/ROT', { method: 'PUT', body: { generate: { length: 4 } } })).status, 400);
  assert.equal((await call('/secrets/ROT', { method: 'PUT', body: { generate: { charset: 'emoji' } } })).status, 400);
  assert.equal((await call('/secrets/ROT', { method: 'PUT', token: tokens.client, body: { generate: {} } })).status, 403);
  const { entries } = await call('/audit').then((x) => x.json());
  const e = entries.find((x) => x.type === 'secret.rotate' && x.name === 'ROT');
  assert.deepEqual(e.generated, { length: 40, charset: 'hex' });
  assert.ok(!JSON.stringify(entries).includes(v));
  const cliR = await cli('smctl.js', ['rotate', 'ROT', '--length', '24', '--charset', 'symbols'], { admin: true });
  assert.equal(cliR.status, 0, cliR.stderr);
  const v2 = (await call('/resolve', { token: tokens.client, method: 'POST' }).then((x) => x.json())).secrets.ROT;
  assert.equal(v2.length, 24);
  assert.notEqual(v2, v);
  assert.ok(!cliR.stderr.includes(v2) && !cliR.stdout.includes(v2));
  assert.notEqual((await cli('smctl.js', ['rotate', 'NOPE_X'], { admin: true })).status, 0);
  await call('/secrets/ROT', { method: 'DELETE' });
});

test('pairing: admin creates a single-use code, another machine claims the client token', async () => {
  assert.equal((await fetch(base + '/v1/pair', { method: 'POST', headers: { Authorization: `Bearer ${tokens.client}` } })).status, 403);
  const p = await call('/pair', { method: 'POST' }).then((r) => r.json());
  assert.match(p.code, /^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
  const claim = (code) => fetch(base + '/v1/pair/claim', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code, device: 'laptop' }) });
  assert.equal((await claim('WRONG-CODE')).status, 403);
  const ok = await claim(p.code.toLowerCase());
  assert.equal(ok.status, 200);
  assert.equal((await ok.json()).token, tokens.client); // never the admin token
  assert.equal((await claim(p.code)).status, 403); // single use
  const { entries } = await call('/audit').then((r) => r.json());
  assert.ok(entries.some((e) => e.type === 'pair.claimed' && e.device === 'laptop'));
  assert.equal((await fetch(base + '/ca.pem')).status, 404); // no CA configured in this test app
});
