// "Last used" / "Uses" count only secrets a command actually used, not every
// secret sm fetched.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SecretStore } from '../server/store.js';
import { createApp, AuditLog } from '../server/app.js';
import { loadTokens } from '../server/index.js';
import { referencedNames } from '../src/shell.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'sm-usage-test-'));
let server, base, tokens, store, audit;

before(async () => {
  tokens = loadTokens(DIR).tokens;
  store = new SecretStore(DIR);
  audit = new AuditLog(path.join(DIR, 'audit.log'));
  const app = createApp({ store, tokens, audit });
  await new Promise((r) => (server = app.listen(0, '127.0.0.1', r)));
  base = `http://127.0.0.1:${server.address().port}`;
  store.set('A_KEY', 'a-value-1111');
  store.set('B_KEY', 'b-value-2222');
  store.set('C_KEY', 'c-value-3333');
  store.set('GITHUB_TOKEN', 'gh-value-4444');
  store.set('A_KEY', 'a-work-5555', '', '', 'work');
});
after(() => {
  server.close();
  fs.rmSync(DIR, { recursive: true, force: true });
});

function sm(args, extra = {}) {
  const env = { ...process.env, SM_CONFIG: path.join(DIR, 'nocfg.json'), SM_SERVER: base, SM_TOKEN: tokens.client, SM_AUDIT: '1', ...extra };
  for (const k of ['SM_BACKEND', 'SM_SCOPES', 'SM_USAGE_FILE', 'A_KEY', 'B_KEY', 'C_KEY', 'GITHUB_TOKEN']) if (!(k in extra)) delete env[k];
  return new Promise((resolve) => {
    const p = spawn('node', [path.join(ROOT, 'bin', 'sm.js'), ...args], { env });
    let stdout = '', stderr = '';
    p.stdout.on('data', (d) => (stdout += d));
    p.stderr.on('data', (d) => (stderr += d));
    p.on('close', (status) => resolve({ status, stdout, stderr }));
    p.stdin.end();
  });
}
const uses = () => Object.fromEntries(store.list().map((s) => [`${s.scope || 'default'}/${s.name}`, s.uses]));

test('referencedNames finds $NAME and ${NAME} of known secrets only', () => {
  const s = { A_KEY: 1, B_KEY: 1 };
  assert.deepEqual([...referencedNames('echo $A_KEY ${B_KEY} $HOME $A_KEYX', s)], ['A_KEY', 'B_KEY']);
});

test('fetching is not a use; only referenced secrets are counted', async () => {
  const r = await sm(['-c', 'true']);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(Object.values(uses()), [0, 0, 0, 0, 0]);

  assert.equal((await sm(['-c', 'test -n "$A_KEY" && echo "{{secret:B_KEY}}" >/dev/null'])).status, 0);
  let u = uses();
  assert.equal(u['default/A_KEY'], 1);
  assert.equal(u['default/B_KEY'], 1);
  assert.equal(u['default/C_KEY'], 0);
  assert.equal(u['work/A_KEY'], 0);
  assert.ok(store.list().find((s) => s.name === 'C_KEY').lastUsedAt === null);
  const cmd = audit.tail(10).entries.find((e) => e.type === 'command');
  assert.deepEqual(cmd.used.sort(), ['A_KEY', 'B_KEY']);

  // With scopes, the use counts in the scope the value came from.
  assert.equal((await sm(['-s', 'default,work', '-c', 'test -n "$A_KEY"'])).status, 0);
  u = uses();
  assert.equal(u['work/A_KEY'], 1);
  assert.equal(u['default/A_KEY'], 1);
});

test('an env placeholder and git-credential-sm count as uses', async () => {
  assert.equal((await sm(['-c', 'test -n "$X"'], { X: '{{secret:C_KEY}}', SM_AUTO_ENV: '0' })).status, 0);
  assert.equal(uses()['default/C_KEY'], 1);

  const helper = path.join(ROOT, 'bin', 'git-credential-sm.js');
  const tmp = fs.mkdtempSync(path.join(DIR, 'tmp-'));
  const r = await sm(['-c', `printf 'protocol=https\\nhost=github.com\\n\\n' | node ${helper} get >/dev/null`], { TMPDIR: tmp });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(uses()['default/GITHUB_TOKEN'], 1);
  assert.deepEqual(fs.readdirSync(tmp), [], 'sm removes its usage file');
});

test('/audit ignores unknown and invalid names', async () => {
  const r = await fetch(base + '/v1/audit', { method: 'POST', headers: { Authorization: `Bearer ${tokens.client}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'command', command: 'x', used: ['NOPE', '../x', 7, 'B_KEY'], scopes: ['bad/scope'] }) });
  assert.equal(r.status, 204);
  assert.equal(uses()['default/B_KEY'], 1);
});
