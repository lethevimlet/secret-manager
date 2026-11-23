// Renaming and deleting categories (per scope); deleting never removes secrets.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { SecretStore } from '../server/store.js';
import { createApp, AuditLog } from '../server/app.js';
import { loadTokens } from '../server/index.js';

const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'sm-cat-test-'));
let server, base, tokens, store, audit;

before(async () => {
  tokens = loadTokens(DIR).tokens;
  store = new SecretStore(DIR);
  audit = new AuditLog(path.join(DIR, 'audit.log'));
  await new Promise((r) => (server = createApp({ store, tokens, audit }).listen(0, '127.0.0.1', r)));
  base = `http://127.0.0.1:${server.address().port}`;
  store.set('A', 'a-value', '', 'Github');
  store.set('B', 'b-value', '', 'Github');
  store.set('C', 'c-value', '', 'Cloud');
  store.set('A', 'w-value', '', 'Github', 'work');
});
after(() => {
  server.close();
  fs.rmSync(DIR, { recursive: true, force: true });
});

const call = (p, body, token = tokens.admin) =>
  fetch(base + '/v1' + p, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const cats = () => Object.fromEntries(store.list().map((s) => [`${s.scope || 'default'}/${s.name}`, s.category]));

test('rename changes only that scope, keeps values, and needs admin', async () => {
  assert.equal((await call('/categories/rename', { from: 'Github', to: 'GitHub' }, tokens.client)).status, 403);
  const r = await call('/categories/rename', { from: 'Github', to: '  GitHub ' });
  assert.equal(r.status, 200);
  assert.deepEqual((await r.json()).names, ['A', 'B']);
  assert.deepEqual(cats(), { 'default/A': 'GitHub', 'default/B': 'GitHub', 'default/C': 'Cloud', 'work/A': 'Github' });
  assert.equal(store.reveal('A'), 'a-value');
  assert.equal(audit.tail(5).entries.find((e) => e.type === 'category.rename').to, 'GitHub');
  assert.equal((await call('/categories/rename', { from: 'GitHub', to: '' })).status, 400);
});

test('renaming onto an existing category merges them', async () => {
  await call('/categories/rename', { from: 'Cloud', to: 'GitHub' });
  assert.equal(cats()['default/C'], 'GitHub');
  await call('/categories/rename', { from: 'GitHub', to: 'Cloud' }); // undo for the next test
});

test('delete moves the secrets to Uncategorized, in that scope only', async () => {
  const r = await call('/categories/delete?scope=work', { name: 'Github' });
  assert.deepEqual((await r.json()).names, ['A']);
  assert.equal(cats()['work/A'], '');
  assert.equal(store.reveal('A', 'work'), 'w-value');
  assert.equal(cats()['default/A'], 'Cloud');
  assert.equal(store.list().length, 4);
  assert.deepEqual((await (await call('/categories/delete', { name: 'Nope' })).json()).names, []);
});
