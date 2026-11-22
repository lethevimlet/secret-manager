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

// ---- used by sm ----
export async function getSecrets() {
  const cfg = loadConfig();
  if (!usesServer(cfg)) return file.loadSecrets();
  return (await request('/resolve', { method: 'POST', body: { pid: process.pid }, cfg })).secrets;
}

export async function recordAudit(entry) {
  const cfg = loadConfig();
  if (!usesServer(cfg)) return file.audit(entry);
  await request('/audit', { method: 'POST', body: entry, cfg, timeoutMs: 2000 });
}

// ---- used by smctl ----
export async function listSecrets() {
  const cfg = loadConfig();
  if (!usesServer(cfg)) return Object.keys(file.loadSecrets()).sort().map((name) => ({ name }));
  return (await request('/secrets', { cfg })).secrets;
}

export async function setSecret(name, value, note, category) {
  const cfg = loadConfig();
  if (!usesServer(cfg)) return file.setSecret(name, value);
  await request(`/secrets/${encodeURIComponent(name)}`, { method: 'PUT', body: { value, note, category }, admin: true, cfg });
}

// Create only; throws `exists` if the name is taken. Client token is enough.
export async function createSecret(name, value, note, category) {
  const cfg = loadConfig();
  if (!usesServer(cfg)) {
    if (name in file.loadSecrets()) throw Object.assign(new Error(`${name} already exists`), { exists: true });
    return file.setSecret(name, value);
  }
  try {
    await request('/secrets', { method: 'POST', body: { name, value, note, category }, cfg });
  } catch (err) {
    if (/already exists/.test(err.message)) err.exists = true;
    throw err;
  }
}

// Replace a value with a random one generated on the server (admin).
export async function rotateSecret(name, length, charset) {
  const cfg = loadConfig();
  if (!usesServer(cfg)) throw new Error('rotate needs the sm server (smctl login)');
  const known = (await request('/secrets', { cfg })).secrets.some((s) => s.name === name);
  if (!known) throw new Error(`no such secret: ${name}`);
  return request(`/secrets/${encodeURIComponent(name)}`, { method: 'PUT', body: { generate: { length, charset } }, admin: true, cfg });
}

export async function removeSecret(name) {
  const cfg = loadConfig();
  if (!usesServer(cfg)) return file.removeSecret(name);
  try {
    await request(`/secrets/${encodeURIComponent(name)}`, { method: 'DELETE', admin: true, cfg });
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
