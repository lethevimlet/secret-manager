// Encrypted secret store for the server.
// Each value is AES-256-GCM encrypted with a random IV; the secret's name is
// bound as additional authenticated data, so a ciphertext can't be moved to
// another name. The master key comes from SM_MASTER_KEY (64 hex chars) or a
// key file next to the data (0600), which only protects a copied data file.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
export const MAX_VALUE_BYTES = 64 * 1024;

// Scopes group secrets so a shell gets only some of them (sm -s work). The
// default scope is '' (shown as "Default"). A secret is identified by scope +
// name, stored under the key "scope/NAME"; default-scope secrets keep the plain
// NAME key, so stores and vaults from before scopes stay valid.
export const SCOPE_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/;
export const DEFAULT_SCOPE = '';

export function cleanScope(s) {
  if (s === undefined || s === null) return DEFAULT_SCOPE;
  if (typeof s !== 'string') throw Object.assign(new Error('scope must be a string'), { status: 400 });
  const v = s.trim().toLowerCase();
  if (v === '' || v === 'default') return DEFAULT_SCOPE;
  if (!SCOPE_RE.test(v)) throw Object.assign(new Error(`invalid scope "${s}": lowercase letters, digits, _ and -, at most 32`), { status: 400 });
  return v;
}

export const keyOf = (name, scope = DEFAULT_SCOPE) => (scope ? `${scope}/${name}` : name);

export function splitKey(key) {
  const i = key.indexOf('/');
  return i === -1 ? { scope: DEFAULT_SCOPE, name: key } : { scope: key.slice(0, i), name: key.slice(i + 1) };
}

export function validKey(key) {
  const { scope, name } = splitKey(String(key));
  return NAME_RE.test(name) && (scope === DEFAULT_SCOPE || SCOPE_RE.test(scope));
}

const badName = () => Object.assign(new Error('invalid name: letters, digits and _, not starting with a digit'), { status: 400 });

// '' = uncategorized. Trimmed, collapsed spaces, at most 40 characters.
export function cleanCategory(c) {
  if (c === undefined || c === null) return undefined;
  if (typeof c !== 'string') throw Object.assign(new Error('category must be a string'), { status: 400 });
  return c.trim().replace(/\s+/g, ' ').slice(0, 40);
}

function writeAtomic(file, text) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, text, { mode: 0o600 });
  fs.renameSync(tmp, file);
}

function loadKey(dir) {
  if (process.env.SM_MASTER_KEY) {
    const key = Buffer.from(process.env.SM_MASTER_KEY, 'hex');
    if (key.length !== 32) throw new Error('SM_MASTER_KEY must be 64 hex characters');
    return key;
  }
  const file = path.join(dir, 'master.key');
  try {
    return Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'hex');
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
    const key = crypto.randomBytes(32);
    writeAtomic(file, key.toString('hex') + '\n');
    return key;
  }
}

export class SecretStore {
  constructor(dir, { device = process.env.SM_DEVICE || os.hostname() } = {}) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.file = path.join(dir, 'secrets.json');
    this.tombFile = path.join(dir, 'tombstones.json');
    this.key = loadKey(dir);
    this.device = device;
    this.onChange = null; // (name) => void, e.g. schedule a vault sync
    try {
      this.data = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      this.data = {};
    }
    // Deleted secrets are remembered (name -> { changedAt, changedBy }) so a sync
    // can tell "deleted here" from "never seen here".
    try {
      this.tombstones = JSON.parse(fs.readFileSync(this.tombFile, 'utf8'));
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      this.tombstones = {};
    }
  }

  save() {
    writeAtomic(this.file, JSON.stringify(this.data, null, 2) + '\n');
  }

  saveTombstones() {
    writeAtomic(this.tombFile, JSON.stringify(this.tombstones, null, 2) + '\n');
  }

  changed(name) {
    try { this.onChange?.(name); } catch {}
  }

  encrypt(name, value) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(Buffer.from(name));
    const data = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
    return { iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') };
  }

  decrypt(name, { iv, tag, data }) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, Buffer.from(iv, 'base64'));
    decipher.setAAD(Buffer.from(name));
    decipher.setAuthTag(Buffer.from(tag, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(data, 'base64')), decipher.final()]).toString('utf8');
  }

  // Metadata only, never values.
  list() {
    return Object.entries(this.data)
      .map(([key, s]) => ({ ...splitKey(key), category: s.category || '', note: s.note || '', createdAt: s.createdAt, updatedAt: s.updatedAt, lastUsedAt: s.lastUsedAt || null, uses: s.uses || 0 }))
      .sort((a, b) => a.scope.localeCompare(b.scope) || a.name.localeCompare(b.name));
  }

  // Scopes that hold at least one secret, besides the default one.
  scopes() {
    return [...new Set(Object.keys(this.data).map((k) => splitKey(k).scope))].filter(Boolean).sort();
  }

  has(name, scope = DEFAULT_SCOPE) {
    return Object.hasOwn(this.data, keyOf(name, cleanScope(scope)));
  }

  set(name, value, note, category, scope = DEFAULT_SCOPE) {
    if (!NAME_RE.test(name)) throw badName();
    scope = cleanScope(scope);
    const key = keyOf(name, scope);
    if (typeof value !== 'string' || value === '') throw Object.assign(new Error('value must be a non-empty string'), { status: 400 });
    if (Buffer.byteLength(value) > MAX_VALUE_BYTES) throw Object.assign(new Error('value too large'), { status: 400 });
    const cat = cleanCategory(category);
    const now = new Date().toISOString();
    const prev = this.data[key];
    this.data[key] = {
      ...this.encrypt(key, value),
      category: cat ?? prev?.category ?? '',
      note: typeof note === 'string' ? note.slice(0, 200) : prev?.note || '',
      createdAt: prev?.createdAt || now,
      updatedAt: now,
      lastUsedAt: prev?.lastUsedAt || null,
      uses: prev?.uses || 0,
      changedAt: now,
      changedBy: this.device,
    };
    this.save();
    if (this.tombstones[key]) { delete this.tombstones[key]; this.saveTombstones(); }
    this.changed(key);
    return !prev;
  }

  // Change metadata (note, category) without touching the value, and/or move
  // the secret to another scope (`to`).
  update(name, { note, category, to }, scope = DEFAULT_SCOPE) {
    scope = cleanScope(scope);
    let key = keyOf(name, scope);
    if (!Object.hasOwn(this.data, key)) return false;
    const cat = cleanCategory(category);
    const now = new Date().toISOString();
    if (to !== undefined && cleanScope(to) !== scope) {
      const newKey = keyOf(name, cleanScope(to));
      if (Object.hasOwn(this.data, newKey)) throw Object.assign(new Error(`${name} already exists in scope ${cleanScope(to) || 'default'}`), { status: 409 });
      // The key is the encryption's associated data: re-encrypt under the new one.
      const value = this.decrypt(key, this.data[key]);
      this.data[newKey] = { ...this.data[key], ...this.encrypt(newKey, value) };
      delete this.data[key];
      this.tombstones[key] = { changedAt: now, changedBy: this.device };
      delete this.tombstones[newKey];
      this.saveTombstones();
      this.changed(key);
      key = newKey;
    }
    if (cat !== undefined) this.data[key].category = cat;
    if (note !== undefined) this.data[key].note = String(note).slice(0, 200);
    this.data[key].changedAt = now;
    this.data[key].changedBy = this.device;
    this.save();
    this.changed(key);
    return true;
  }

  categories() {
    return [...new Set(Object.values(this.data).map((s) => s.category || ''))].filter(Boolean).sort((a, b) => a.localeCompare(b));
  }

  remove(name, scope = DEFAULT_SCOPE) {
    const key = keyOf(name, cleanScope(scope));
    if (!Object.hasOwn(this.data, key)) return false;
    delete this.data[key];
    this.save();
    this.tombstones[key] = { changedAt: new Date().toISOString(), changedBy: this.device };
    this.saveTombstones();
    this.changed(key);
    return true;
  }

  // ---- vault sync ----

  // Delete a scope and every secret in it. Returns the deleted names.
  removeScope(scope) {
    scope = cleanScope(scope);
    if (!scope) throw Object.assign(new Error('the default scope cannot be deleted'), { status: 400 });
    const names = Object.keys(this.data).map(splitKey).filter((k) => k.scope === scope).map((k) => k.name).sort();
    for (const n of names) this.remove(n, scope);
    return names;
  }

  // Sync works on keys ("scope/NAME", or NAME in the default scope): every key
  // this store knows, live or deleted.
  syncNames() {
    return [...new Set([...Object.keys(this.data), ...Object.keys(this.tombstones)])];
  }

  // The synced state of one name: value + metadata, or a deletion marker.
  syncEntry(name) {
    const s = this.data[name];
    if (s) {
      return {
        name, value: this.decrypt(name, s), category: s.category || '', note: s.note || '',
        createdAt: s.createdAt, changedAt: s.changedAt || s.updatedAt, changedBy: s.changedBy || this.device,
      };
    }
    const t = this.tombstones[name];
    return t ? { name, deleted: true, changedAt: t.changedAt, changedBy: t.changedBy } : null;
  }

  // Apply an entry that won against the local state (from another server).
  // Does not trigger onChange: it is not a local change to push back.
  applySyncEntry(e) {
    if (e.deleted) {
      if (this.data[e.name]) { delete this.data[e.name]; this.save(); }
      this.tombstones[e.name] = { changedAt: e.changedAt, changedBy: e.changedBy };
      this.saveTombstones();
      return;
    }
    if (!validKey(e.name) || typeof e.value !== 'string' || !e.value) throw new Error(`invalid synced entry ${e.name}`);
    const prev = this.data[e.name];
    this.data[e.name] = {
      ...this.encrypt(e.name, e.value),
      category: cleanCategory(e.category ?? '') || '',
      note: String(e.note ?? '').slice(0, 200),
      createdAt: prev?.createdAt || e.createdAt || e.changedAt,
      updatedAt: e.changedAt,
      lastUsedAt: prev?.lastUsedAt || null,
      uses: prev?.uses || 0,
      changedAt: e.changedAt,
      changedBy: e.changedBy,
    };
    this.save();
    if (this.tombstones[e.name]) { delete this.tombstones[e.name]; this.saveTombstones(); }
  }

  // Raw AES-256-GCM with the master key, for other small files (vault key).
  sealRaw(buf, aad) {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    c.setAAD(Buffer.from(aad));
    const data = Buffer.concat([c.update(buf), c.final()]);
    return { iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), data: data.toString('base64') };
  }

  openRaw({ iv, tag, data }, aad) {
    const d = crypto.createDecipheriv('aes-256-gcm', this.key, Buffer.from(iv, 'base64'));
    d.setAAD(Buffer.from(aad));
    d.setAuthTag(Buffer.from(tag, 'base64'));
    return Buffer.concat([d.update(Buffer.from(data, 'base64')), d.final()]);
  }

  // One value, for the owner viewing it in the GUI. Not counted as a use.
  reveal(name, scope = DEFAULT_SCOPE) {
    const key = keyOf(name, cleanScope(scope));
    return Object.hasOwn(this.data, key) ? this.decrypt(key, this.data[key]) : null;
  }

  // The values of the given scopes, for the sm shell; marks them as used.
  // A name in several scopes takes the value of the last scope listed
  // (reported in `overridden`). `empty` = requested scopes with no secrets.
  resolve(scopes = [DEFAULT_SCOPE]) {
    const list = [...new Set(scopes.map(cleanScope))];
    const secrets = Object.create(null);
    const from = new Map(); // name -> scope it came from
    const overridden = [];
    const now = new Date().toISOString();
    for (const scope of list) {
      for (const [key, s] of Object.entries(this.data)) {
        const k = splitKey(key);
        if (k.scope !== scope) continue;
        if (from.has(k.name)) overridden.push({ name: k.name, scope: from.get(k.name), by: scope });
        secrets[k.name] = this.decrypt(key, s);
        from.set(k.name, scope);
        s.lastUsedAt = now;
        s.uses = (s.uses || 0) + 1;
      }
    }
    if (Object.keys(secrets).length) this.save();
    const used = new Set(from.values());
    return { secrets, scopes: list, overridden, empty: list.filter((s) => !used.has(s)) };
  }

  // All scopes at once (the old behaviour; only for tests and tools).
  resolveAll() {
    return this.resolve(['', ...this.scopes()]).secrets;
  }
}
