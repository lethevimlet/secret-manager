// Encrypted secret store for the server.
// Each value is AES-256-GCM encrypted with a random IV; the secret's name is
// bound as additional authenticated data, so a ciphertext can't be moved to
// another name. The master key comes from SM_MASTER_KEY (64 hex chars) or a
// key file next to the data (0600), which only protects a copied data file.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
export const MAX_VALUE_BYTES = 64 * 1024;

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
  constructor(dir) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.file = path.join(dir, 'secrets.json');
    this.key = loadKey(dir);
    try {
      this.data = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      this.data = {};
    }
  }

  save() {
    writeAtomic(this.file, JSON.stringify(this.data, null, 2) + '\n');
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
      .map(([name, s]) => ({ name, category: s.category || '', note: s.note || '', createdAt: s.createdAt, updatedAt: s.updatedAt, lastUsedAt: s.lastUsedAt || null, uses: s.uses || 0 }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  has(name) {
    return Object.hasOwn(this.data, name);
  }

  set(name, value, note, category) {
    if (!NAME_RE.test(name)) throw Object.assign(new Error('invalid name: letters, digits and _, not starting with a digit'), { status: 400 });
    if (typeof value !== 'string' || value === '') throw Object.assign(new Error('value must be a non-empty string'), { status: 400 });
    if (Buffer.byteLength(value) > MAX_VALUE_BYTES) throw Object.assign(new Error('value too large'), { status: 400 });
    const cat = cleanCategory(category);
    const now = new Date().toISOString();
    const prev = this.data[name];
    this.data[name] = {
      ...this.encrypt(name, value),
      category: cat ?? prev?.category ?? '',
      note: typeof note === 'string' ? note.slice(0, 200) : prev?.note || '',
      createdAt: prev?.createdAt || now,
      updatedAt: now,
      lastUsedAt: prev?.lastUsedAt || null,
      uses: prev?.uses || 0,
    };
    this.save();
    return !prev;
  }

  // Change metadata (note and/or category) without touching the value.
  update(name, { note, category }) {
    if (!this.has(name)) return false;
    const cat = cleanCategory(category);
    if (cat !== undefined) this.data[name].category = cat;
    if (note !== undefined) this.data[name].note = String(note).slice(0, 200);
    this.save();
    return true;
  }

  categories() {
    return [...new Set(Object.values(this.data).map((s) => s.category || ''))].filter(Boolean).sort((a, b) => a.localeCompare(b));
  }

  remove(name) {
    if (!this.has(name)) return false;
    delete this.data[name];
    this.save();
    return true;
  }

  // All values, for the sm shell. Marks them as used.
  resolveAll() {
    const out = {};
    const now = new Date().toISOString();
    for (const [name, s] of Object.entries(this.data)) {
      out[name] = this.decrypt(name, s);
      s.lastUsedAt = now;
      s.uses = (s.uses || 0) + 1;
    }
    if (Object.keys(out).length) this.save();
    return out;
  }
}
