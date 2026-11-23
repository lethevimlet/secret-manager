// sm-vault: keep several sm servers in sync through a private git repository.
//
// The repository only ever holds ciphertext:
//   vault.json                   { format, version, vaultId }      (no secrets)
//   secrets/<hmac(name)>.json    one file per secret, AES-256-GCM with the vault key
// File names are an HMAC of the secret's name, so neither names nor values are
// visible on the git host; only the number of secrets and when they change.
//
// The vault key (random, 256 bits) is never in the repository. It travels in a
// key file (sm-vault.key) encrypted with a key derived from the user's password
// (scrypt). Every server that joins unlocks it once and keeps it locally,
// sealed with its own master key. A leaked repository alone can't be attacked by
// guessing the password: there is nothing in it to test a guess against.
//
// Sync: newer change wins per secret (changedAt, tie broken by device name);
// deletions are kept as tombstones so an offline server can't bring a deleted
// secret back. Conflicts (changed on two servers since the last sync) are logged.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';

export const KEYFILE_FORMAT = 'sm-vault-key';
const SCRYPT = { N: 2 ** 17, r: 8, p: 1, keylen: 32 };
const SCRYPT_MAXMEM = 256 * 1024 * 1024;

const b64 = (buf) => buf.toString('base64');
const unb64 = (s) => Buffer.from(s, 'base64');

function scrypt(password, salt, p) {
  return new Promise((resolve, reject) =>
    crypto.scrypt(String(password).normalize('NFC'), salt, p.keylen, { N: p.N, r: p.r, p: p.p, maxmem: SCRYPT_MAXMEM }, (err, key) => (err ? reject(err) : resolve(key))),
  );
}

function seal(key, plaintext, aad) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from(aad));
  const data = Buffer.concat([c.update(plaintext), c.final()]);
  return { iv: b64(iv), tag: b64(c.getAuthTag()), data: b64(data) };
}

function open(key, box, aad) {
  const d = crypto.createDecipheriv('aes-256-gcm', key, unb64(box.iv));
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(unb64(box.tag));
  return Buffer.concat([d.update(unb64(box.data)), d.final()]);
}

// ---- key file ----

export async function createKeyFile({ vaultKey, vaultId, repo, password }) {
  if (typeof password !== 'string' || [...password].length < 10) throw Object.assign(new Error('the password must be at least 10 characters'), { status: 400 });
  const salt = crypto.randomBytes(16);
  const wrap = await scrypt(password, salt, SCRYPT);
  return {
    format: KEYFILE_FORMAT,
    version: 1,
    vaultId,
    repo,
    kdf: { name: 'scrypt', N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, salt: b64(salt) },
    key: seal(wrap, vaultKey, `sm-vault-key:${vaultId}`),
    createdAt: new Date().toISOString(),
    note: 'sm-vault key file. Keep a copy offline: without it the vault cannot be decrypted. Unlocked with your sm password.',
  };
}

export async function openKeyFile(keyFile, password) {
  if (!keyFile || keyFile.format !== KEYFILE_FORMAT || keyFile.version !== 1) throw Object.assign(new Error('not an sm-vault key file'), { status: 400 });
  const k = keyFile.kdf;
  const wrap = await scrypt(password, unb64(k.salt), { N: k.N, r: k.r, p: k.p, keylen: 32 });
  let vaultKey;
  try {
    vaultKey = open(wrap, keyFile.key, `sm-vault-key:${keyFile.vaultId}`);
  } catch {
    throw Object.assign(new Error('wrong password for this key file'), { status: 403 });
  }
  return { vaultKey, vaultId: keyFile.vaultId, repo: keyFile.repo };
}

// ---- entries ----

export const entryFileName = (vaultKey, name) => crypto.createHmac('sha256', vaultKey).update(`name:${name}`).digest('hex').slice(0, 32) + '.json';

export function sealEntry(vaultKey, vaultId, entry) {
  const file = entryFileName(vaultKey, entry.name);
  return { v: 1, ...seal(vaultKey, Buffer.from(JSON.stringify(entry)), `${vaultId}:${file}`) };
}

export function openEntry(vaultKey, vaultId, file, box) {
  const entry = JSON.parse(open(vaultKey, box, `${vaultId}:${file}`).toString('utf8'));
  if (entryFileName(vaultKey, entry.name) !== file) throw new Error(`entry ${file} does not match its name`);
  return entry;
}

// Which of two versions of a secret wins: newer changedAt, ties by device name.
export function newer(a, b) {
  const ta = Date.parse(a.changedAt) || 0;
  const tb = Date.parse(b.changedAt) || 0;
  if (ta !== tb) return ta > tb ? a : b;
  return String(a.changedBy) >= String(b.changedBy) ? a : b;
}

const sameVersion = (a, b) => a.changedAt === b.changedAt && a.changedBy === b.changedBy;

// Deploy keys work over SSH only: turn https://github.com/OWNER/REPO(.git)
// (the address GitHub shows by default) into git@github.com:OWNER/REPO.git.
export function normalizeRepo(repo) {
  const r = String(repo || '').trim();
  const m = /^https?:\/\/(?:[^@/]+@)?(github\.com|gitlab\.com|codeberg\.org|bitbucket\.org)\/([^/\s]+)\/([^/\s]+?)(?:\.git)?\/?$/i.exec(r);
  return m ? `git@${m[1].toLowerCase()}:${m[2]}/${m[3]}.git` : r;
}

// git's last error line, phrased for the user (status 400, not "internal error").
function gitError(err, repo) {
  const msg = err.message;
  let hint = '';
  if (/read only|read-only|denied to deploy key|write access/i.test(msg)) {
    hint = ' The deploy key has no write access: tick "Allow write access" for it in the repository settings.';
  } else if (/Permission denied \(publickey\)|Could not read from remote repository|Repository not found|does not appear to be a git repository/i.test(msg)) {
    hint = ' The server can\'t reach the repository: check the address, and that this server\'s deploy key is added to it with write access.';
  } else if (/could not read Username|terminal prompts disabled/i.test(msg)) {
    hint = ' Use the SSH address (git@github.com:you/sm-vault.git): deploy keys don\'t work over HTTPS.';
  }
  return Object.assign(new Error(`${msg}.${hint}`.replace(/\.\./, '.')), { status: 400, repo });
}

// ---- sync ----

export class Vault {
  constructor({ dir, store, audit = null, intervalMs = 5 * 60_000, debounceMs = 5_000 }) {
    this.dir = dir;
    this.store = store;
    this.audit = audit;
    this.intervalMs = intervalMs;
    this.debounceMs = debounceMs;
    this.stateFile = path.join(dir, 'vault.json');
    this.keyStoreFile = path.join(dir, 'vault.key');
    this.repoDir = path.join(dir, 'vault-repo');
    this.deployKey = path.join(dir, 'vault-deploy-key');
    this.state = null;
    this.vaultKey = null;
    this.running = Promise.resolve();
    this.syncing = false;
    this.timer = null;
    this.debounce = null;
    try {
      this.state = JSON.parse(fs.readFileSync(this.stateFile, 'utf8'));
      this.vaultKey = store.openRaw(JSON.parse(fs.readFileSync(this.keyStoreFile, 'utf8')), `vault-key:${this.state.vaultId}`);
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      this.state = null;
    }
  }

  get configured() {
    return Boolean(this.state && this.vaultKey);
  }

  status() {
    if (!this.configured) return { configured: false };
    const { repo, vaultId, lastSync, lastResult, lastError } = this.state;
    // local = secrets on this server now; lastResult.vault/.local = both counts right after the last sync.
    const nextSync = this.timerStart ? new Date(this.timerStart + Math.ceil((Date.now() - this.timerStart + 1) / this.intervalMs) * this.intervalMs).toISOString() : null;
    return { configured: true, repo, vaultId, device: this.store.device, lastSync, lastResult, lastError: lastError || null, syncing: this.syncing, local: this.store.list().length, intervalMs: this.intervalMs, nextSync };
  }

  saveState() {
    fs.writeFileSync(this.stateFile + '.tmp', JSON.stringify(this.state, null, 2) + '\n', { mode: 0o600 });
    fs.renameSync(this.stateFile + '.tmp', this.stateFile);
  }

  gitEnv() {
    const env = { ...process.env, GIT_TERMINAL_PROMPT: '0' };
    if (fs.existsSync(this.deployKey)) {
      const known = path.join(this.dir, 'vault-known-hosts');
      env.GIT_SSH_COMMAND = `ssh -i ${this.deployKey} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=${known} -o BatchMode=yes`;
    }
    return env;
  }

  git(args, { cwd = this.repoDir, allowFail = false } = {}) {
    return new Promise((resolve, reject) => {
      execFile('git', args, { cwd, env: this.gitEnv(), timeout: 120_000, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
        if (err && !allowFail) return reject(new Error(`git ${args[0]}: ${(stderr || err.message).trim().split('\n').pop()}`));
        resolve({ ok: !err, stdout: String(stdout), stderr: String(stderr) });
      });
    });
  }

  // Generate this server's SSH deploy key for the git host (once).
  async deployPublicKey() {
    if (!fs.existsSync(this.deployKey)) {
      await new Promise((resolve, reject) =>
        execFile('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', `sm-vault@${this.store.device}`, '-f', this.deployKey], (err) => (err ? reject(err) : resolve())),
      );
      fs.chmodSync(this.deployKey, 0o600);
    }
    return fs.readFileSync(this.deployKey + '.pub', 'utf8').trim();
  }

  async clone(repo) {
    fs.rmSync(this.repoDir, { recursive: true, force: true });
    await this.git(['clone', '--quiet', repo, this.repoDir], { cwd: this.dir }).catch((err) => { throw gitError(err, repo); });
    await this.git(['config', 'user.name', `sm-server (${this.store.device})`]);
    await this.git(['config', 'user.email', 'sm-server@localhost']);
  }

  readRepoVault() {
    try { return JSON.parse(fs.readFileSync(path.join(this.repoDir, 'vault.json'), 'utf8')); } catch { return null; }
  }

  // First server: new vault key, empty vault in the (empty) repository, push
  // every local secret. Returns the key file to hand to the user.
  async init({ repo, password }) {
    repo = normalizeRepo(repo);
    if (this.configured) throw Object.assign(new Error('this server is already connected to a vault'), { status: 409 });
    await this.clone(repo);
    if (this.readRepoVault()) throw Object.assign(new Error('that repository already holds a vault: join it with its key file instead'), { status: 409 });
    const vaultKey = crypto.randomBytes(32);
    const vaultId = crypto.randomBytes(16).toString('hex');
    const keyFile = await createKeyFile({ vaultKey, vaultId, repo, password });
    fs.writeFileSync(path.join(this.repoDir, 'vault.json'), JSON.stringify({ format: 'sm-vault', version: 1, vaultId, createdAt: new Date().toISOString() }, null, 2) + '\n');
    fs.writeFileSync(path.join(this.repoDir, 'README.md'),
      '# sm-vault\n\nEncrypted secrets of the [sm secret manager](https://github.com/lethevimlet/secret-manager).\n' +
      'Every file under `secrets/` is AES-256-GCM ciphertext; file names are keyed hashes of the secret names.\n' +
      'The key is not in this repository: it is in the `sm-vault.key` file, unlocked with the sm password.\n' +
      'Do not edit by hand. Servers sync with `smctl sync`.\n');
    fs.mkdirSync(path.join(this.repoDir, 'secrets'), { recursive: true });
    fs.writeFileSync(path.join(this.repoDir, 'secrets', '.gitkeep'), '');
    await this.git(['add', '-A']);
    await this.git(['commit', '--quiet', '-m', `sm-vault created by ${this.store.device}`]);
    await this.git(['push', '--quiet', 'origin', 'HEAD:main']).catch((err) => { throw gitError(err, repo); });
    this.adopt({ repo, vaultId, vaultKey });
    await this.syncNow('init');
    return keyFile;
  }

  // Another server: unlock the key file, check it belongs to the repository's
  // vault, then sync (pulls everything, pushes what only this server has).
  async join({ keyFile, password }) {
    if (this.configured) throw Object.assign(new Error('this server is already connected to a vault'), { status: 409 });
    const { vaultKey, vaultId } = await openKeyFile(keyFile, password);
    const repo = normalizeRepo(keyFile.repo);
    await this.clone(repo);
    const remote = this.readRepoVault();
    if (!remote) throw Object.assign(new Error('the repository holds no vault (run smctl sync init on the first server)'), { status: 409 });
    if (remote.vaultId !== vaultId) throw Object.assign(new Error('this key file belongs to a different vault'), { status: 409 });
    this.adopt({ repo, vaultId, vaultKey });
    await this.syncNow('join');
    return this.status();
  }

  adopt({ repo, vaultId, vaultKey }) {
    this.vaultKey = vaultKey;
    this.state = { repo, vaultId, lastSync: null, lastResult: null, lastError: null };
    fs.writeFileSync(this.keyStoreFile, JSON.stringify(this.store.sealRaw(vaultKey, `vault-key:${vaultId}`)) + '\n', { mode: 0o600 });
    this.saveState();
  }

  // One sync cycle, serialized: concurrent calls wait for each other.
  syncNow(reason = 'manual') {
    const run = this.running.then(() => this.cycle(reason));
    this.running = run.catch(() => {});
    return run;
  }

  async cycle(reason) {
    if (!this.configured) throw Object.assign(new Error('not connected to a vault'), { status: 409 });
    this.syncing = true;
    const lastSync = this.state.lastSync ? Date.parse(this.state.lastSync) : 0;
    const result = { pulled: 0, pushed: 0, conflicts: [] };
    try {
      for (let attempt = 1; ; attempt++) {
        result.pulled = 0; result.pushed = 0; result.conflicts = [];
        await this.git(['fetch', '--quiet', 'origin']);
        await this.git(['reset', '--quiet', '--hard', 'origin/main']);
        await this.git(['clean', '-qfd']);
        const remoteVault = this.readRepoVault();
        if (!remoteVault || remoteVault.vaultId !== this.state.vaultId) throw new Error('the repository no longer holds this vault');

        const secretsDir = path.join(this.repoDir, 'secrets');
        fs.mkdirSync(secretsDir, { recursive: true });
        const remote = new Map();
        for (const f of fs.readdirSync(secretsDir)) {
          if (!f.endsWith('.json')) continue;
          const e = openEntry(this.vaultKey, this.state.vaultId, f, JSON.parse(fs.readFileSync(path.join(secretsDir, f), 'utf8')));
          remote.set(e.name, e);
        }
        const names = new Set([...remote.keys(), ...this.store.syncNames()]);
        result.vault = 0; // secrets (not deletions) in the vault once this cycle is pushed
        for (const name of names) {
          const local = this.store.syncEntry(name);
          const rem = remote.get(name);
          let winner;
          if (!rem) winner = local;
          else if (!local) winner = rem;
          else if (sameVersion(local, rem)) {
            if (!rem.deleted) result.vault++;
            continue;
          }
          else {
            winner = newer(local, rem);
            const both = Date.parse(local.changedAt) > lastSync && Date.parse(rem.changedAt) > lastSync && local.changedBy !== rem.changedBy;
            if (both) result.conflicts.push({ name, kept: winner.changedBy, lost: (winner === local ? rem : local).changedBy });
          }
          if (!winner.deleted) result.vault++;
          if (winner === local) {
            fs.writeFileSync(path.join(secretsDir, entryFileName(this.vaultKey, name)), JSON.stringify(sealEntry(this.vaultKey, this.state.vaultId, local)) + '\n');
            result.pushed++;
          } else {
            this.store.applySyncEntry(rem);
            result.pulled++;
          }
        }
        if (!result.pushed) break;
        await this.git(['add', '-A']);
        await this.git(['commit', '--quiet', '-m', `sync from ${this.store.device}: ${result.pushed} change(s)`]);
        const push = await this.git(['push', '--quiet', 'origin', 'HEAD:main'], { allowFail: true });
        if (push.ok) break;
        if (attempt >= 3) throw new Error(`push rejected 3 times: ${push.stderr.trim().split('\n').pop()}`);
        // Another server pushed in between: start over from its state.
      }
      this.state.lastSync = new Date().toISOString();
      this.state.lastResult = { pulled: result.pulled, pushed: result.pushed, conflicts: result.conflicts.length, vault: result.vault, local: this.store.list().length };
      this.state.lastError = null;
      this.saveState();
      if (this.audit) {
        if (result.pulled || result.pushed) this.audit.add({ type: 'sync', reason, pulled: result.pulled, pushed: result.pushed });
        for (const c of result.conflicts) this.audit.add({ type: 'sync.conflict', name: c.name, kept: c.kept, lost: c.lost });
      }
      return { ...this.state.lastResult, conflictNames: result.conflicts.map((c) => c.name) };
    } catch (err) {
      this.state.lastError = err.message;
      this.saveState();
      this.audit?.add({ type: 'sync.error', reason, error: err.message.slice(0, 300) });
      throw err;
    } finally {
      this.syncing = false;
    }
  }

  exportKeyFile(password) {
    if (!this.configured) throw Object.assign(new Error('not connected to a vault'), { status: 409 });
    return createKeyFile({ vaultKey: this.vaultKey, vaultId: this.state.vaultId, repo: this.state.repo, password });
  }

  // Periodic pull + push shortly after local changes.
  start() {
    this.store.onChange = () => {
      if (!this.configured) return;
      clearTimeout(this.debounce);
      this.debounce = setTimeout(() => this.syncNow('change').catch(() => {}), this.debounceMs);
      this.debounce.unref?.();
    };
    this.timerStart = Date.now();
    this.timer = setInterval(() => { if (this.configured) this.syncNow('timer').catch(() => {}); }, this.intervalMs);
    this.timer.unref?.();
    if (this.configured) setTimeout(() => this.syncNow('startup').catch(() => {}), 2000).unref?.();
  }

  stop() {
    clearInterval(this.timer);
    clearTimeout(this.debounce);
  }
}
