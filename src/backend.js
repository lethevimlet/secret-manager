// Where sm/smctl get secrets from: the sm-server (when configured with
// `smctl login`) or the local file store (SM_BACKEND=file, or no config).
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import * as file from './store.js';

export function configPath() {
  return process.env.SM_CONFIG || path.join(os.homedir(), '.config', 'sm', 'config.json');
}

export function loadConfig() {
  let cfg = {};
  try {
    cfg = JSON.parse(fs.readFileSync(configPath(), 'utf8'));
  } catch (err) {
    if (err.code !== 'ENOENT') throw new Error(`bad config ${configPath()}: ${err.message}`);
  }
  if (process.env.SM_SERVER) cfg.server = process.env.SM_SERVER;
  if (process.env.SM_TOKEN) cfg.token = process.env.SM_TOKEN;
  if (process.env.SM_ADMIN_TOKEN) cfg.adminToken = process.env.SM_ADMIN_TOKEN;
  return cfg;
}

export function saveConfig(cfg) {
  const p = configPath();
  fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o700 });
  fs.writeFileSync(p + '.tmp', JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(p + '.tmp', p);
}

export function usesServer(cfg = loadConfig()) {
  return process.env.SM_BACKEND !== 'file' && Boolean(cfg.server);
}

// node:http(s) instead of fetch so a private CA (cfg.ca, a PEM file path) can
// be trusted without changing the process-wide trust store.
export async function request(pathname, { method = 'GET', body, admin = false, cfg = loadConfig(), timeoutMs = 5000 } = {}) {
  const tok = admin ? cfg.adminToken : cfg.token || cfg.adminToken;
  if (!tok) throw new Error(admin ? 'no admin token configured (smctl login)' : 'no token configured (smctl login)');
  const url = new URL('/v1' + pathname, cfg.server);
  const lib = url.protocol === 'https:' ? https : http;
  const payload = body ? JSON.stringify(body) : null;
  const opts = {
    method,
    headers: { Authorization: `Bearer ${tok}`, ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}) },
    timeout: timeoutMs,
  };
  if (url.protocol === 'https:' && cfg.ca) opts.ca = fs.readFileSync(cfg.ca);
  const { status, text } = await new Promise((resolve, reject) => {
    const req = lib.request(url, opts, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (d) => (text += d));
      res.on('end', () => resolve({ status: res.statusCode, text }));
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
    req.on('error', (err) => reject(new Error(`secret server ${cfg.server} unreachable (${err.code || err.message})`)));
    req.end(payload ?? undefined);
  });
  if (status === 204) return null;
  let data = {};
  try { data = JSON.parse(text); } catch {}
  if (status < 200 || status >= 300) throw new Error(data.error || `HTTP ${status}`);
  return data;
}

// Unauthenticated request (pairing). `ca` = PEM file to trust; `insecure` only
// for fetching the CA itself, whose fingerprint the user then confirms.
export function publicRequest(server, pathname, { method = 'GET', body, ca, insecure = false, timeoutMs = 8000, raw = false } = {}) {
  const url = new URL(pathname, server);
  const lib = url.protocol === 'https:' ? https : http;
  const payload = body ? JSON.stringify(body) : null;
  const opts = { method, timeout: timeoutMs, headers: payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {} };
  if (url.protocol === 'https:') {
    if (ca) opts.ca = fs.readFileSync(ca);
    if (insecure) opts.rejectUnauthorized = false;
  }
  return new Promise((resolve, reject) => {
    const req = lib.request(url, opts, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (d) => (text += d));
      res.on('end', () => {
        if (raw) return res.statusCode === 200 ? resolve(text) : reject(new Error(`HTTP ${res.statusCode} for ${url.pathname}`));
        let data = {};
        try { data = JSON.parse(text); } catch {}
        if (res.statusCode < 200 || res.statusCode >= 300) reject(new Error(data.error || `HTTP ${res.statusCode}`));
        else resolve(data);
      });
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
    req.on('error', (err) => reject(new Error(`${server} unreachable (${err.code || err.message})`)));
    req.end(payload ?? undefined);
  });
}

// ---- used by sm ----
// `scopes`: list of scope names ('default' = the default scope); none = default.
// Returns { secrets, overridden, empty } (see the server's /resolve).
export async function getSecrets(scopes = []) {
  const cfg = loadConfig();
  if (!usesServer(cfg)) {
    if (scopes.some((s) => s !== 'default')) throw new Error('scopes need the sm server (smctl login); the local file store has only the default scope');
    return { secrets: file.loadSecrets(), overridden: [], empty: [] };
  }
  return request('/resolve', { method: 'POST', body: { pid: process.pid, ...(scopes.length && { scopes }) }, cfg });
}

const q = (scope) => (scope && scope !== 'default' ? `?scope=${encodeURIComponent(scope)}` : '');
const noScopes = (scope) => {
  if (scope && scope !== 'default') throw new Error('scopes need the sm server (smctl login)');
};

export async function recordAudit(entry) {
  const cfg = loadConfig();
  if (!usesServer(cfg)) return file.audit(entry);
  await request('/audit', { method: 'POST', body: entry, cfg, timeoutMs: 2000 });
}

// ---- used by smctl ----
export async function listSecrets() {
  const cfg = loadConfig();
  if (!usesServer(cfg)) return Object.keys(file.loadSecrets()).sort().map((name) => ({ name, scope: '' }));
  return (await request('/secrets', { cfg })).secrets;
}

export async function setSecret(name, value, note, category, scope) {
  const cfg = loadConfig();
  if (!usesServer(cfg)) return noScopes(scope), file.setSecret(name, value);
  await request(`/secrets/${encodeURIComponent(name)}${q(scope)}`, { method: 'PUT', body: { value, note, category }, admin: true, cfg });
}

// Create only; throws `exists` if the name is taken. Client token is enough.
export async function createSecret(name, value, note, category, scope) {
  const cfg = loadConfig();
  if (!usesServer(cfg)) {
    noScopes(scope);
    if (name in file.loadSecrets()) throw Object.assign(new Error(`${name} already exists`), { exists: true });
    return file.setSecret(name, value);
  }
  try {
    await request('/secrets', { method: 'POST', body: { name, value, note, category, scope }, cfg });
  } catch (err) {
    if (/already exists/.test(err.message)) err.exists = true;
    throw err;
  }
}

// Replace a value with a random one generated on the server (admin).
export async function rotateSecret(name, length, charset, scope) {
  const cfg = loadConfig();
  if (!usesServer(cfg)) throw new Error('rotate needs the sm server (smctl login)');
  const want = scope && scope !== 'default' ? scope : '';
  const known = (await request('/secrets', { cfg })).secrets.some((s) => s.name === name && (s.scope || '') === want);
  if (!known) throw new Error(`no such secret: ${name}${want ? ` in scope ${want}` : ''}`);
  return request(`/secrets/${encodeURIComponent(name)}${q(scope)}`, { method: 'PUT', body: { generate: { length, charset } }, admin: true, cfg });
}

// Move a secret to another scope (admin).
export async function moveSecret(name, from, to) {
  const cfg = loadConfig();
  if (!usesServer(cfg)) throw new Error('scopes need the sm server (smctl login)');
  return request(`/secrets/${encodeURIComponent(name)}${q(from)}`, { method: 'PATCH', body: { to }, admin: true, cfg });
}

export async function removeSecret(name, scope) {
  const cfg = loadConfig();
  if (!usesServer(cfg)) return noScopes(scope), file.removeSecret(name);
  try {
    await request(`/secrets/${encodeURIComponent(name)}${q(scope)}`, { method: 'DELETE', admin: true, cfg });
    return true;
  } catch (err) {
    if (err.message === 'no such secret') return false;
    throw err;
  }
}

export async function readAudit(limit) {
  const cfg = loadConfig();
  if (!usesServer(cfg)) {
    try {
      return fs.readFileSync(file.auditFile(), 'utf8').trim().split('\n').slice(-limit).map((l) => JSON.parse(l)).reverse();
    } catch (err) {
      if (err.code === 'ENOENT') return [];
      throw err;
    }
  }
  return (await request(`/audit?limit=${limit}`, { admin: true, cfg })).entries;
}
