// HTTP API + GUI for the secret store.
//   admin token:  manage secrets, read the audit log (GUI, smctl)
//   client token: fetch values and report command audits (the sm shell)
// Values are write-only through the admin API: the GUI can replace a value but
// never read it back.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import { fileURLToPath } from 'node:url';
import { COOKIE, MIN_PASSWORD, readCookie, isLoopback } from './auth.js';
import { generateValue } from '../src/generate.js';

const PUBLIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'public');

function sameToken(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// Append-only JSON lines, pruned by age and count: at start-up and every 200
// appends, entries older than `days` go, and at most `max` newest are kept.
export class AuditLog {
  constructor(file, { days = 30, max = 10000 } = {}) {
    this.file = file;
    this.days = days;
    this.max = max;
    this.sinceTrim = 0;
    this.prune();
  }

  read() {
    try {
      return fs.readFileSync(this.file, 'utf8').split('\n').filter(Boolean).map((l) => {
        try { return JSON.parse(l); } catch { return null; }
      }).filter(Boolean);
    } catch (err) {
      if (err.code === 'ENOENT') return [];
      throw err;
    }
  }

  prune() {
    const all = this.read();
    const cutoff = this.days > 0 ? Date.now() - this.days * 86400_000 : -Infinity;
    let kept = all.filter((e) => Date.parse(e.time) >= cutoff);
    if (this.max > 0 && kept.length > this.max) kept = kept.slice(-this.max);
    if (kept.length !== all.length) {
      const tmp = `${this.file}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, kept.map((e) => JSON.stringify(e)).join('\n') + (kept.length ? '\n' : ''), { mode: 0o600 });
      fs.renameSync(tmp, this.file);
    }
    this.sinceTrim = 0;
    return all.length - kept.length;
  }

  add(entry) {
    fs.appendFileSync(this.file, JSON.stringify({ time: new Date().toISOString(), ...entry }) + '\n', { mode: 0o600 });
    if (++this.sinceTrim >= 200) this.prune();
  }

  // Newest first.
  tail(limit) {
    const all = this.read();
    return { entries: all.slice(-limit).reverse(), total: all.length };
  }
}

export function createApp({ store, tokens, audit, noAuth = false, guiAuth = null, caPem = null, vault = null }) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', false);

  app.use((req, res, next) => {
    res.set({
      'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    });
    next();
  });

  app.get('/health', (_req, res) => res.json({ ok: true }));
  // Public CA certificate (not a secret) so other machines can trust the HTTPS
  // listener; clients show its fingerprint for the user to compare.
  app.get('/ca.pem', (_req, res) => (caPem ? res.type('application/x-pem-file').send(caPem) : res.status(404).json({ error: 'no CA configured (SM_TLS_CA)' })));
  app.use(express.static(PUBLIC_DIR, { index: 'index.html', maxAge: 0 }));

  const api = express.Router();
  api.use(express.json({ limit: '128kb' }));
  api.use((_req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });

  // ---- GUI password login (before the token check) ----
  const ip = (req) => (req.socket.remoteAddress || '').replace(/^::ffff:/, '');
  const setCookie = (req, res, id, maxAge) =>
    res.cookie(COOKIE, id, { httpOnly: true, sameSite: 'strict', secure: Boolean(req.socket.encrypted), path: '/', maxAge });
  const fail = (res, status, error, extra = {}) => res.status(status).json({ error, ...extra });

  if (guiAuth) {
    api.get('/auth/status', (req, res) =>
      res.json({
        passwordSet: guiAuth.passwordSet,
        loggedIn: guiAuth.checkSession(readCookie(req, COOKIE)),
        setupNeedsCode: !guiAuth.passwordSet && !isLoopback(req),
        minPassword: MIN_PASSWORD,
      }));

    api.post('/auth/setup', async (req, res) => {
      if (guiAuth.passwordSet) return fail(res, 409, 'a password is already set');
      const wait = guiAuth.blockedFor(ip(req));
      if (wait) return fail(res, 429, `too many attempts, wait ${wait} s`);
      if (!isLoopback(req) && !guiAuth.checkSetupCode(req.body?.code)) {
        guiAuth.noteFailure(ip(req));
        audit.add({ type: 'auth.setup-failed', ip: ip(req) });
        return fail(res, 403, 'wrong setup code (run smctl setup-code on the server)');
      }
      await guiAuth.setPassword(req.body?.password);
      audit.add({ type: 'auth.setup', ip: ip(req) });
      const { id, maxAge } = guiAuth.createSession();
      setCookie(req, res, id, maxAge);
      res.status(201).json({ ok: true });
    });

    api.post('/auth/login', async (req, res) => {
      if (!guiAuth.passwordSet) return fail(res, 409, 'no password set yet');
      const wait = guiAuth.blockedFor(ip(req));
      if (wait) return fail(res, 429, `too many wrong passwords, wait ${wait} s`, { retryAfter: wait });
      if (!(await guiAuth.verify(req.body?.password))) {
        guiAuth.noteFailure(ip(req));
        audit.add({ type: 'auth.login-failed', ip: ip(req) });
        return fail(res, 401, 'wrong password');
      }
      guiAuth.noteSuccess(ip(req));
      audit.add({ type: 'auth.login', ip: ip(req) });
      const { id, maxAge } = guiAuth.createSession();
      setCookie(req, res, id, maxAge);
      res.json({ ok: true });
    });

    api.post('/auth/logout', (req, res) => {
      guiAuth.endSession(readCookie(req, COOKIE));
      res.clearCookie(COOKIE, { path: '/' });
      res.status(204).end();
    });
  }

  // ---- Pairing another machine: one-time code -> client token ----
  const pairCodes = new Map(); // code -> { expires, by }
  const pairFails = new Map(); // ip -> { count, until }
  const PAIR_TTL = 10 * 60_000;
  api.post('/pair/claim', (req, res) => {
    const f = pairFails.get(ip(req));
    if (f && f.until > Date.now()) return fail(res, 429, `too many wrong codes, wait ${Math.ceil((f.until - Date.now()) / 1000)} s`);
    const code = String(req.body?.code || '').trim().toUpperCase();
    const entry = pairCodes.get(code);
    if (!entry || entry.expires < Date.now()) {
      const n = (f?.count || 0) + 1;
      pairFails.set(ip(req), { count: n, until: n >= 5 ? Date.now() + Math.min(2 ** (n - 5), 900) * 1000 : 0 });
      audit.add({ type: 'pair.failed', ip: ip(req) });
      return fail(res, 403, 'wrong or expired pairing code (create one with smctl pair on the server)');
    }
    pairCodes.delete(code); // single use
    pairFails.delete(ip(req));
    const device = String(req.body?.device || '').slice(0, 80);
    audit.add({ type: 'pair.claimed', ip: ip(req), device });
    res.json({ token: tokens.client, scope: 'client' });
  });

  // Resolve the caller's scope: bearer token, or a GUI session cookie.
  api.use((req, res, next) => {
    const m = /^Bearer (.+)$/.exec(req.get('authorization') || '');
    if (m && sameToken(m[1], tokens.admin)) req.scope = 'admin';
    else if (m && sameToken(m[1], tokens.client)) req.scope = 'client';
    else if (!m && guiAuth && guiAuth.checkSession(readCookie(req, COOKIE))) {
      // Cookies are sent by the browser automatically, so changes made with
      // one must carry a header other sites can't add (CSRF guard).
      if (req.method !== 'GET' && req.get('x-sm-gui') !== '1') return res.status(403).json({ error: 'missing X-SM-GUI header' });
      req.scope = 'admin';
      req.session = true;
    } else if (noAuth && !m) {
      // Testing mode: management without a token, but never secret values.
      req.scope = 'admin';
      req.anonymous = true;
    } else return res.status(401).json({ error: 'missing or invalid token' });
    next();
  });
  const need = (scope) => (req, res, next) =>
    scope === 'client' || req.scope === 'admin' ? next() : res.status(403).json({ error: `${scope} token required` });

  api.get('/whoami', (req, res) => res.json({ scope: req.scope, anonymous: Boolean(req.anonymous), session: Boolean(req.session) }));

  // Admin: create a pairing code for another machine.
  api.post('/pair', need('admin'), (req, res) => {
    if (req.anonymous) return fail(res, 401, 'pairing needs the admin token or a signed-in GUI');
    for (const [c, e] of pairCodes) if (e.expires < Date.now()) pairCodes.delete(c);
    const code = crypto.randomBytes(6).toString('base64url').toUpperCase().replace(/[^A-Z0-9]/g, '').padEnd(8, 'X').slice(0, 8);
    const pretty = `${code.slice(0, 4)}-${code.slice(4)}`;
    pairCodes.set(pretty, { expires: Date.now() + PAIR_TTL });
    audit.add({ type: 'pair.created', by: req.session ? 'gui' : 'admin token', ip: ip(req) });
    res.json({ code: pretty, expiresInSeconds: PAIR_TTL / 1000, caFingerprint: caPem ? new crypto.X509Certificate(caPem).fingerprint256 : null });
  });

  // Admin: one-time setup code / change or reset the GUI password.
  if (guiAuth) {
    api.get('/auth/setup-code', need('admin'), (req, res) => {
      if (req.session) return fail(res, 403, 'admin token required');
      res.json({ code: guiAuth.getSetupCode(), passwordSet: guiAuth.passwordSet });
    });
    api.put('/auth/password', need('admin'), async (req, res) => {
      // With a GUI session the current password is required; with the admin
      // token (smctl passwd) it's not, so a forgotten password can be reset.
      if (req.session && !(await guiAuth.verify(req.body?.current))) return fail(res, 401, 'current password is wrong');
      await guiAuth.setPassword(req.body?.password);
      audit.add({ type: 'auth.password', by: req.session ? 'gui' : 'admin token', ip: ip(req) });
      if (req.session) {
        const { id, maxAge } = guiAuth.createSession();
        setCookie(req, res, id, maxAge);
      }
      res.json({ ok: true });
    });
  }

  // ---- sm-vault: sync with other servers through a private git repository ----
  if (vault) {
    const owner = (req, res, next) => (req.anonymous ? fail(res, 401, 'the vault needs the admin token or a signed-in GUI') : next());
    // The key file is locked with the GUI password: check it, so the copy the
    // user carries around opens with the password they actually use.
    const checkPassword = async (password) => {
      if (typeof password !== 'string' || !password) throw Object.assign(new Error('password required'), { status: 400 });
      if (guiAuth?.passwordSet && !(await guiAuth.verify(password))) throw Object.assign(new Error('that is not this server\'s GUI password'), { status: 403 });
    };
    api.get('/vault', need('admin'), owner, (_req, res) => res.json(vault.status()));
    api.get('/vault/deploy-key', need('admin'), owner, async (_req, res) => res.json({ publicKey: await vault.deployPublicKey() }));
    api.post('/vault/init', need('admin'), owner, async (req, res) => {
      const { repo, password } = req.body || {};
      if (typeof repo !== 'string' || !repo) return fail(res, 400, 'repo required');
      await checkPassword(password);
      const keyFile = await vault.init({ repo, password });
      audit.add({ type: 'vault.init', repo, by: req.session ? 'gui' : 'admin token', ip: ip(req) });
      res.json({ keyFile, status: vault.status() });
    });
    api.post('/vault/join', need('admin'), owner, async (req, res) => {
      const { keyFile, password } = req.body || {};
      const status = await vault.join({ keyFile, password }).catch((err) => {
        if (err.status === 403) audit.add({ type: 'vault.join-failed', ip: ip(req) });
        throw err;
      });
      // A new server takes the vault's password as its GUI password.
      if (guiAuth && !guiAuth.passwordSet) await guiAuth.setPassword(password);
      audit.add({ type: 'vault.join', repo: status.repo, by: req.session ? 'gui' : 'admin token', ip: ip(req) });
      res.json({ status });
    });
    api.post('/vault/sync', need('admin'), owner, async (_req, res) => res.json({ result: await vault.syncNow('manual'), status: vault.status() }));
    // A fresh copy of the key file, locked with the current GUI password.
    api.post('/vault/key-file', need('admin'), owner, async (req, res) => {
      await checkPassword(req.body?.password);
      res.json({ keyFile: await vault.exportKeyFile(req.body.password) });
    });
  }

  api.get('/secrets', (_req, res) => res.json({ secrets: store.list(), categories: store.categories() }));

  // Create only (agents, via sm-add with the client token): never replaces.
  api.post('/secrets', (req, res) => {
    const { name, value, note, category } = req.body || {};
    if (typeof name !== 'string') return res.status(400).json({ error: 'name required' });
    if (store.has(name)) return res.status(409).json({ error: `${name} already exists` });
    store.set(name, value, note, category);
    audit.add({ type: 'secret.create', name, by: req.anonymous ? 'anonymous' : req.scope });
    res.status(201).json({ name, created: true });
  });

  api.put('/secrets/:name', need('admin'), (req, res) => {
    const { name } = req.params;
    const { note, category, generate } = req.body || {};
    // `generate: { length, charset }` = a random value made here, so it never
    // travels over the network or through the browser (rotation).
    const value = generate ? generateValue(generate.length ?? 12, generate.charset ?? 'alnum') : req.body?.value;
    const created = store.set(name, value, note, category);
    const type = created ? 'secret.create' : generate ? 'secret.rotate' : 'secret.update';
    audit.add({ type, name, ...(generate && { generated: { length: value.length, charset: generate.charset ?? 'alnum' } }), by: req.anonymous ? 'anonymous' : 'admin' });
    res.status(created ? 201 : 200).json({ name, created, ...(generate && { generated: true, length: value.length }) });
  });

  api.patch('/secrets/:name', need('admin'), (req, res) => {
    const { name } = req.params;
    const { note, category } = req.body || {};
    if (typeof note !== 'string' && typeof category !== 'string') return res.status(400).json({ error: 'note or category required' });
    if (!store.update(name, { note: typeof note === 'string' ? note : undefined, category })) return res.status(404).json({ error: 'no such secret' });
    audit.add({ type: 'secret.edit', name, ...(typeof category === 'string' && { category: store.list().find((x) => x.name === name).category }), by: req.anonymous ? 'anonymous' : 'admin' });
    res.json({ name });
  });

  api.delete('/secrets/:name', need('admin'), (req, res) => {
    const { name } = req.params;
    if (!store.remove(name)) return res.status(404).json({ error: 'no such secret' });
    audit.add({ type: 'secret.delete', name, by: req.anonymous ? 'anonymous' : 'admin' });
    res.status(204).end();
  });

  // One value, for the owner in the GUI. Always needs the real admin token,
  // also when SM_NO_AUTH=1 lets the rest of the GUI work without one.
  api.post('/secrets/:name/reveal', (req, res) => {
    if (req.scope !== 'admin' || req.anonymous) return res.status(401).json({ error: 'viewing values needs the admin token', needAdminToken: true });
    const value = store.reveal(req.params.name);
    if (value === null) return res.status(404).json({ error: 'no such secret' });
    audit.add({ type: 'secret.reveal', name: req.params.name, by: 'admin', ip: req.socket.remoteAddress });
    res.json({ name: req.params.name, value });
  });

  // All values, for the sm shell.
  api.post('/resolve', (req, res) => {
    if (req.anonymous) return res.status(401).json({ error: 'fetching values always needs a token' });
    const secrets = store.resolveAll();
    audit.add({ type: 'resolve', by: req.scope, count: Object.keys(secrets).length, pid: req.body?.pid ?? null });
    res.json({ secrets });
  });

  api.post('/audit', (req, res) => {
    const e = req.body || {};
    audit.add({
      type: 'command',
      by: req.scope,
      mode: String(e.mode || ''),
      command: typeof e.command === 'string' ? e.command.slice(0, 4000) : JSON.stringify(e.command ?? '').slice(0, 4000),
      placeholders: Array.isArray(e.placeholders) ? e.placeholders.slice(0, 100).map(String) : [],
      redactions: e.redactions && typeof e.redactions === 'object' ? e.redactions : {},
      exit: Number.isInteger(e.exit) ? e.exit : null,
      cwd: typeof e.cwd === 'string' ? e.cwd.slice(0, 500) : null,
    });
    res.status(204).end();
  });

  api.get('/audit', need('admin'), (req, res) => {
    const limit = Math.min(Math.max(Number(req.query.limit) || 200, 1), 2000);
    res.json({ ...audit.tail(limit), retention: { days: audit.days, max: audit.max } });
  });

  app.use('/v1', api);

  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    if (status >= 500) console.error(err);
    res.status(status).json({ error: status >= 500 ? 'internal error' : err.message });
  });

  return app;
}
