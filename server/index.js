#!/usr/bin/env node
// sm-server: local secret manager API + GUI.
//   SM_PORT          default 8737
//   SM_BIND          default 127.0.0.1 (localhost only)
//   SM_SERVER_DATA   default <project>/.sm-server
//   SM_MASTER_KEY    optional 64-hex master key (else a key file in the data dir)
//   SM_TLS_CERT, SM_TLS_KEY   certificate for HTTPS
//   SM_TLS_CA        CA certificate that signed it; served at /ca.pem for other machines
//   SM_AUDIT_DAYS    keep activity this many days (default 30, 0 = no age limit)
//   SM_AUDIT_MAX     keep at most this many activity entries (default 10000, 0 = no limit)
//   SM_NO_AUTH=1     TESTING ONLY: manage secrets without a token (values still need one)
//   SM_LAN_BIND      optional extra HTTPS listener, e.g. 192.168.1.10 (SM_LAN_PORT, default SM_PORT)
import crypto from 'node:crypto';
import fs from 'node:fs';
import https from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SecretStore } from './store.js';
import { createApp, AuditLog } from './app.js';
import { GuiAuth } from './auth.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DEFAULT_DATA = path.join(ROOT, '.sm-server');

export function loadTokens(dir) {
  const file = path.join(dir, 'tokens.json');
  try {
    return { tokens: JSON.parse(fs.readFileSync(file, 'utf8')), created: false };
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
    const tokens = {
      admin: 'sma_' + crypto.randomBytes(24).toString('base64url'),
      client: 'smc_' + crypto.randomBytes(24).toString('base64url'),
    };
    fs.writeFileSync(file, JSON.stringify(tokens, null, 2) + '\n', { mode: 0o600 });
    return { tokens, created: true };
  }
}

const isMain = process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const dir = process.env.SM_SERVER_DATA || DEFAULT_DATA;
  const port = Number(process.env.SM_PORT || 8737);
  const host = process.env.SM_BIND || '127.0.0.1';

  const store = new SecretStore(dir);
  const { tokens, created } = loadTokens(dir);
  const noAuth = process.env.SM_NO_AUTH === '1';
  const guiAuth = new GuiAuth(dir);
  if (!guiAuth.passwordSet) console.log('GUI: no password yet; set it on first visit (from another machine: smctl setup-code)');
  const app = createApp({ store, tokens, audit: new AuditLog(path.join(dir, 'audit.log'), { days: Number(process.env.SM_AUDIT_DAYS ?? 30), max: Number(process.env.SM_AUDIT_MAX ?? 10000) }), noAuth, guiAuth, caPem: process.env.SM_TLS_CA ? fs.readFileSync(process.env.SM_TLS_CA, 'utf8') : null });
  if (noAuth) console.warn('WARNING: SM_NO_AUTH=1, anyone who can reach the server can add, replace and delete secrets');

  // Listener 1: plain HTTP on loopback, for sm/smctl on this machine.
  // Listener 2 (optional): HTTPS on a LAN address, for the GUI and remote clients.
  const listeners = [];
  const tls = process.env.SM_TLS_CERT && process.env.SM_TLS_KEY
    ? { cert: fs.readFileSync(process.env.SM_TLS_CERT), key: fs.readFileSync(process.env.SM_TLS_KEY) }
    : null;
  const loopback = ['127.0.0.1', '::1', 'localhost'].includes(host);
  if (!tls && !loopback) {
    console.error('refusing to serve plain HTTP on a non-loopback address; set SM_TLS_CERT and SM_TLS_KEY');
    process.exit(1);
  }
  const start = (srv, h, p, scheme) =>
    listeners.push(srv.listen(p, h, () => console.log(`sm-server listening on ${scheme}://${h.includes(':') ? `[${h}]` : h}:${p}  (data: ${dir})`)));
  start(tls && !loopback ? https.createServer(tls, app) : app, host, port, tls && !loopback ? 'https' : 'http');
  if (process.env.SM_LAN_BIND) {
    if (!tls) {
      console.error('SM_LAN_BIND needs SM_TLS_CERT and SM_TLS_KEY');
      process.exit(1);
    }
    start(https.createServer(tls, app), process.env.SM_LAN_BIND, Number(process.env.SM_LAN_PORT || port), 'https');
  }
  if (created) console.log(`new tokens written to ${path.join(dir, 'tokens.json')}`);
  console.log('connect the CLI:  smctl login      open the GUI:  smctl gui');
  for (const l of listeners) l.on('error', (err) => { console.error(err.message); process.exit(1); });
  const stop = () => Promise.all(listeners.map((l) => new Promise((r) => l.close(r)))).then(() => process.exit(0));
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}
