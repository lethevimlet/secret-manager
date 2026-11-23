// sm-vault: two servers syncing through a local bare git repository.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { SecretStore } from '../server/store.js';
import { Vault, openKeyFile, newer, normalizeRepo } from '../server/vault.js';

const PASSWORD = 'correct horse battery';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function setup() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sm-vault-test-'));
  const repo = path.join(root, 'sm-vault.git');
  execFileSync('git', ['init', '--quiet', '--bare', '-b', 'main', repo]);
  const server = (name) => {
    const dir = path.join(root, name);
    const store = new SecretStore(dir, { device: name });
    const events = [];
    const vault = new Vault({ dir, store, audit: { add: (e) => events.push(e) } });
    return { dir, store, vault, events };
  };
  return { root, repo, server, cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}

const repoFiles = (repo) => execFileSync('git', ['--git-dir', repo, 'ls-tree', '-r', '--name-only', 'main']).toString().trim().split('\n');
const repoText = (repo) => execFileSync('git', ['--git-dir', repo, 'log', '-p', '--all']).toString();

test('init, join, sync both ways; the repository holds neither names nor values', async () => {
  const t = setup();
  try {
    const a = t.server('alpha');
    a.store.set('API_KEY', 'sk-alpha-value-123', 'an api', 'Cloud');
    a.store.set('DB_PASS', 'db-secret-456');
    const keyFile = await a.vault.init({ repo: t.repo, password: PASSWORD });
    assert.equal(keyFile.repo, t.repo);
    assert.equal(a.vault.status().lastResult.pushed, 2);

    await assert.rejects(openKeyFile(keyFile, 'wrong password!!'), /wrong password/);

    const b = t.server('beta');
    b.store.set('ONLY_ON_B', 'beta-value-789');
    await b.vault.join({ keyFile: JSON.parse(JSON.stringify(keyFile)), password: PASSWORD });
    assert.equal(b.store.reveal('API_KEY'), 'sk-alpha-value-123');
    assert.deepEqual(b.store.list().find((s) => s.name === 'API_KEY'), { ...b.store.list().find((s) => s.name === 'API_KEY'), category: 'Cloud', note: 'an api' });

    await a.vault.syncNow();
    assert.equal(a.store.reveal('ONLY_ON_B'), 'beta-value-789');

    const files = repoFiles(t.repo);
    assert.ok(files.includes('vault.json'));
    assert.equal(files.filter((f) => f.startsWith('secrets/') && f.endsWith('.json')).length, 3);
    const history = repoText(t.repo);
    for (const leak of ['API_KEY', 'DB_PASS', 'ONLY_ON_B', 'sk-alpha-value-123', 'db-secret-456', 'beta-value-789', 'Cloud', 'an api']) {
      assert.ok(!history.includes(leak), `repository history contains ${leak}`);
    }
    // The vault key is neither in the repository nor in plain form on disk.
    const vaultKeyHex = (await openKeyFile(keyFile, PASSWORD)).vaultKey.toString('hex');
    assert.ok(!history.includes(vaultKeyHex));
    assert.ok(!fs.readFileSync(path.join(a.dir, 'vault.key'), 'utf8').includes(vaultKeyHex));

    // A restarted server reopens its vault from disk.
    const again = new Vault({ dir: a.dir, store: a.store });
    assert.equal(again.configured, true);
    assert.equal((await again.syncNow()).pulled, 0);
  } finally {
    t.cleanup();
  }
});

test('deletions propagate and an offline server does not bring a deleted secret back', async () => {
  const t = setup();
  try {
    const a = t.server('alpha');
    a.store.set('OLD_TOKEN', 'old-value-1');
    a.store.set('KEEP', 'keep-value');
    const keyFile = await a.vault.init({ repo: t.repo, password: PASSWORD });
    const b = t.server('beta');
    await b.vault.join({ keyFile, password: PASSWORD });
    assert.equal(b.store.reveal('OLD_TOKEN'), 'old-value-1');

    await sleep(5);
    a.store.remove('OLD_TOKEN');
    await a.vault.syncNow();
    // b still has it (offline) and syncs later: the newer deletion wins.
    const r = await b.vault.syncNow();
    assert.equal(r.pulled, 1);
    assert.equal(b.store.has('OLD_TOKEN'), false);
    assert.equal(b.store.reveal('KEEP'), 'keep-value');

    // Re-creating it after the deletion is a newer change and comes back.
    await sleep(5);
    b.store.set('OLD_TOKEN', 'new-value-2');
    await b.vault.syncNow();
    await a.vault.syncNow();
    assert.equal(a.store.reveal('OLD_TOKEN'), 'new-value-2');
  } finally {
    t.cleanup();
  }
});

test('the same secret changed on two servers: newer wins everywhere, conflict is logged', async () => {
  const t = setup();
  try {
    const a = t.server('alpha');
    a.store.set('SHARED', 'v0');
    const keyFile = await a.vault.init({ repo: t.repo, password: PASSWORD });
    const b = t.server('beta');
    await b.vault.join({ keyFile, password: PASSWORD });

    await sleep(5);
    a.store.set('SHARED', 'from-alpha');
    await sleep(5);
    b.store.set('SHARED', 'from-beta-newer');
    await a.vault.syncNow();
    const rb = await b.vault.syncNow();
    assert.deepEqual(rb.conflictNames, ['SHARED']);
    await a.vault.syncNow();
    assert.equal(a.store.reveal('SHARED'), 'from-beta-newer');
    assert.equal(b.store.reveal('SHARED'), 'from-beta-newer');
    assert.ok(b.events.some((e) => e.type === 'sync.conflict' && e.name === 'SHARED' && e.kept === 'beta' && e.lost === 'alpha'));
  } finally {
    t.cleanup();
  }
});

test('metadata-only edits (category, note) sync too', async () => {
  const t = setup();
  try {
    const a = t.server('alpha');
    a.store.set('X', 'x-value');
    const keyFile = await a.vault.init({ repo: t.repo, password: PASSWORD });
    const b = t.server('beta');
    await b.vault.join({ keyFile, password: PASSWORD });
    await sleep(5);
    b.store.update('X', { category: 'Infra', note: 'moved' });
    await b.vault.syncNow();
    await a.vault.syncNow();
    const x = a.store.list().find((s) => s.name === 'X');
    assert.equal(x.category, 'Infra');
    assert.equal(x.note, 'moved');
    assert.equal(a.store.reveal('X'), 'x-value');
  } finally {
    t.cleanup();
  }
});

test('servers syncing at the same time both end up with everything (push retry)', async () => {
  const t = setup();
  try {
    const a = t.server('alpha');
    const keyFile = await a.vault.init({ repo: t.repo, password: PASSWORD });
    const b = t.server('beta');
    await b.vault.join({ keyFile, password: PASSWORD });
    for (let i = 0; i < 5; i++) {
      a.store.set(`A_${i}`, `a-${i}`);
      b.store.set(`B_${i}`, `b-${i}`);
    }
    await Promise.all([a.vault.syncNow(), b.vault.syncNow()]);
    await Promise.all([a.vault.syncNow(), b.vault.syncNow()]);
    for (const s of [a, b]) for (let i = 0; i < 5; i++) {
      assert.equal(s.store.reveal(`A_${i}`), `a-${i}`);
      assert.equal(s.store.reveal(`B_${i}`), `b-${i}`);
    }
  } finally {
    t.cleanup();
  }
});

test('a key file of another vault, a non-empty repository and a short password are refused', async () => {
  const t = setup();
  try {
    const a = t.server('alpha');
    await assert.rejects(a.vault.init({ repo: t.repo, password: 'short' }), /at least 10/);
    const keyFile = await a.vault.init({ repo: t.repo, password: PASSWORD });

    const other = setup();
    try {
      const c = other.server('gamma');
      const otherKey = await c.vault.init({ repo: other.repo, password: PASSWORD });
      const b = t.server('beta');
      await assert.rejects(b.vault.join({ keyFile: { ...otherKey, repo: t.repo }, password: PASSWORD }), /different vault/);
      const d = t.server('delta');
      await assert.rejects(d.vault.init({ repo: t.repo, password: PASSWORD }), /already holds a vault/);
      await assert.rejects(a.vault.join({ keyFile, password: PASSWORD }), /already connected/);
    } finally {
      other.cleanup();
    }
  } finally {
    t.cleanup();
  }
});

test('newer(): timestamp first, device name breaks ties', () => {
  const x = { changedAt: '2026-11-23T10:00:00.000Z', changedBy: 'alpha' };
  const y = { changedAt: '2026-11-23T10:00:01.000Z', changedBy: 'alpha' };
  const z = { changedAt: '2026-11-23T10:00:00.000Z', changedBy: 'beta' };
  assert.equal(newer(x, y), y);
  assert.equal(newer(x, z), z);
  assert.equal(newer(z, x), z);
});

test('HTTPS repository addresses become SSH (deploy keys need SSH); others stay as given', () => {
  assert.equal(normalizeRepo('https://github.com/you/sm-vault'), 'git@github.com:you/sm-vault.git');
  assert.equal(normalizeRepo(' https://github.com/you/sm-vault.git/ '), 'git@github.com:you/sm-vault.git');
  assert.equal(normalizeRepo('git@github.com:you/sm-vault.git'), 'git@github.com:you/sm-vault.git');
  assert.equal(normalizeRepo('/srv/git/sm-vault.git'), '/srv/git/sm-vault.git');
});

test('an unreachable repository is a readable 400, not an internal error', async () => {
  const t = setup();
  try {
    const a = t.server('alpha');
    await assert.rejects(a.vault.init({ repo: path.join(t.root, 'missing.git'), password: PASSWORD }), (err) => err.status === 400 && /git clone/.test(err.message));
    assert.equal(a.vault.configured, false);
  } finally {
    t.cleanup();
  }
});
