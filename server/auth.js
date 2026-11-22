// GUI password + sessions.
//
// The password is stored only as a scrypt hash (random 16-byte salt,
// N=2^15, r=8, p=1) in <data>/auth.json (0600). Logging in creates a random
// session id kept in memory (a server restart signs everyone out) and sent as
// an HttpOnly, SameSite=Strict cookie. Wrong passwords are slowed down per IP.
// Until a password exists, it can be set from the server itself (loopback)
// or from elsewhere with a one-time setup code (`smctl setup-code`).
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const SCRYPT = { N: 2 ** 15, r: 8, p: 1, keylen: 64, maxmem: 64 * 1024 * 1024 };
export const MIN_PASSWORD = 10;
const SESSION_MS = 12 * 3600_000;
export const COOKIE = 'sm_session';

function scrypt(password, salt, params) {
  return new Promise((resolve, reject) =>
    crypto.scrypt(password, salt, params.keylen, { N: params.N, r: params.r, p: params.p, maxmem: SCRYPT.maxmem }, (err, key) => (err ? reject(err) : resolve(key))),
  );
}

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

function writeAtomic(file, text) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, text, { mode: 0o600 });
  fs.renameSync(tmp, file);
}

export class GuiAuth {
  constructor(dir) {
    this.file = path.join(dir, 'auth.json');
    this.sessions = new Map(); // sha256(session id) -> expires (ms)
    this.failures = new Map(); // ip -> { count, until }
    this.setupCode = null;
    try {
      this.record = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      this.record = null;
    }
  }

  get passwordSet() {
    return Boolean(this.record);
  }

  // One-time code for setting the first password from another machine.
  getSetupCode() {
    if (this.passwordSet) return null;
    if (!this.setupCode) this.setupCode = crypto.randomBytes(5).toString('hex').toUpperCase().match(/.{1,5}/g).join('-');
    return this.setupCode;
  }

  checkSetupCode(code) {
    const want = this.getSetupCode();
    const got = String(code || '').trim().toUpperCase();
    return Boolean(want) && got.length === want.length && crypto.timingSafeEqual(Buffer.from(got), Buffer.from(want));
  }

  async setPassword(password) {
    if (typeof password !== 'string' || [...password].length < MIN_PASSWORD) {
      throw Object.assign(new Error(`password must be at least ${MIN_PASSWORD} characters`), { status: 400 });
    }
    if (password.length > 1024) throw Object.assign(new Error('password too long'), { status: 400 });
    const salt = crypto.randomBytes(16);
    const hash = await scrypt(password.normalize('NFC'), salt, SCRYPT);
    this.record = {
      scheme: 'scrypt',
      N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, keylen: SCRYPT.keylen,
      salt: salt.toString('base64'),
      hash: hash.toString('base64'),
      updatedAt: new Date().toISOString(),
    };
    writeAtomic(this.file, JSON.stringify(this.record, null, 2) + '\n');
    this.setupCode = null;
    this.sessions.clear(); // a new password signs every session out
  }

  async verify(password) {
    if (!this.record || typeof password !== 'string') return false;
    const r = this.record;
    const key = await scrypt(password.normalize('NFC'), Buffer.from(r.salt, 'base64'), r);
    const want = Buffer.from(r.hash, 'base64');
    return key.length === want.length && crypto.timingSafeEqual(key, want);
  }

  // Brute-force brake: after 5 wrong passwords from an IP, wait 2^(n-5) s (max 15 min).
  blockedFor(ip) {
    const f = this.failures.get(ip);
    return f && f.until > Date.now() ? Math.ceil((f.until - Date.now()) / 1000) : 0;
  }

  noteFailure(ip) {
    const f = this.failures.get(ip) || { count: 0, until: 0 };
    f.count += 1;
    if (f.count >= 5) f.until = Date.now() + Math.min(2 ** (f.count - 5), 900) * 1000;
    this.failures.set(ip, f);
  }

  noteSuccess(ip) {
    this.failures.delete(ip);
  }

  createSession() {
    const id = crypto.randomBytes(32).toString('base64url');
    this.sessions.set(sha256(id), Date.now() + SESSION_MS);
    return { id, maxAge: SESSION_MS };
  }

  checkSession(id) {
    if (!id) return false;
    const key = sha256(id);
    const exp = this.sessions.get(key);
    if (!exp) return false;
    if (exp < Date.now()) {
      this.sessions.delete(key);
      return false;
    }
    return true;
  }

  endSession(id) {
    if (id) this.sessions.delete(sha256(id));
  }
}

export function readCookie(req, name) {
  for (const part of (req.headers.cookie || '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
}

export function isLoopback(req) {
  const a = req.socket.remoteAddress || '';
  return a === '127.0.0.1' || a === '::1' || a === '::ffff:127.0.0.1';
}
