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
  assert.match(await res.text(), /Secret manager/);
});

test('SM_NO_AUTH: manage without a token, values still need one', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sm-noauth-'));
  const t = loadTokens(dir).tokens;
  const app = createApp({ store: new SecretStore(dir), tokens: t, audit: new AuditLog(path.join(dir, 'audit.log')), noAuth: true });
  const srv = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  const u = `http://127.0.0.1:${srv.address().port}/v1`;
  try {
    assert.deepEqual(await fetch(u + '/whoami').then((r) => r.json()), { scope: 'admin', anonymous: true });
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
