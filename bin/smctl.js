#!/usr/bin/env node
// smctl: manage secrets (on the sm-server once logged in, else the local file store).
//   smctl login [--server URL] [--data DIR] [--token T --admin-token A] [--ca PEM] [--gui-url URL]
//   smctl login --server https://HOST:8737 --code XXXX-XXXX [--ca PEM | --ca-fingerprint SHA256]   (another machine)
//   smctl pair                one-time code for another machine (prints the command to run there)
//   smctl status
//   smctl gui [URL] [--no-open]   print (and try to open) the GUI URL, signed in
//   smctl setup-code          one-time code to set the first GUI password from another machine
//   smctl passwd              set/reset the GUI password (admin token; new password on stdin or prompted)
//   smctl set NAME [--note TEXT] [--category NAME]   value from stdin (never argv)
//   smctl list                names only
//   smctl rotate NAME [--length N (12)] [--charset alnum|hex|base64url|symbols]   new random value, made on the server
//   smctl rm NAME
//   smctl env                 `export NAME='{{secret:NAME}}'` lines
//   smctl audit [N]
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import os from 'node:os';
import readline from 'node:readline/promises';
import { fileURLToPath } from 'node:url';
import { NAME_RE } from '../src/store.js';
import { placeholder } from '../src/placeholders.js';
import * as backend from '../src/backend.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_SERVER = 'http://127.0.0.1:8737';
const [, , command, ...rest] = process.argv;

function flag(name) {
  const i = rest.indexOf(name);
  if (i === -1) return undefined;
  const v = rest[i + 1];
  rest.splice(i, 2);
  return v;
}

async function readValue(name) {
  if (!process.stdin.isTTY) {
    let data = '';
    for await (const chunk of process.stdin) data += chunk;
    return data.replace(/\r?\n$/, '');
  }
  process.stderr.write(`value for ${name}: `);
  process.stdin.setRawMode(true);
  let value = '';
  for await (const chunk of process.stdin) {
    for (const ch of chunk.toString('utf8')) {
      if (ch === '\r' || ch === '\n') {
        process.stdin.setRawMode(false);
        process.stderr.write('\n');
        return value;
      }
      if (ch === '\u0003') process.exit(130);
      if (ch === '\u007f') value = value.slice(0, -1);
      else value += ch;
    }
  }
  return value;
}

// Download the server's CA certificate (not secret), check its fingerprint
// against --ca-fingerprint or ask the user, and save it next to the config.
async function fetchCa(server, wantFp) {
  const pem = await backend.publicRequest(server, '/ca.pem', { insecure: true, raw: true }).catch((err) => {
    throw new Error(`could not get the server's CA certificate (${err.message}); pass --ca /path/to/ca.crt`);
  });
  const fp = new crypto.X509Certificate(pem).fingerprint256;
  const norm = (x) => String(x).replace(/[^0-9a-f]/gi, '').toUpperCase();
  if (wantFp) {
    if (norm(wantFp) !== norm(fp)) throw new Error(`CA fingerprint mismatch: server sent ${fp}`);
  } else {
    process.stderr.write(`Server CA fingerprint:\n  ${fp}\nCompare it with the one printed by \`smctl pair\` on the server.\n`);
    if (!process.stdin.isTTY) throw new Error('not confirmed: pass --ca-fingerprint (non-interactive)');
    const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
    const ok = /^y(es)?$/i.test((await rl.question('Do they match? [y/N] ')).trim());
    rl.close();
    if (!ok) throw new Error('CA not trusted, nothing changed');
  }
  const file = path.join(path.dirname(backend.configPath()), 'ca.pem');
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, pem, { mode: 0o644 });
  return file;
}

const fmtTime = (iso) => (iso ? iso.replace('T', ' ').slice(0, 19) : '-');

async function main() {
  switch (command) {
    case 'login': {
      const server = flag('--server') || DEFAULT_SERVER;
      let token = flag('--token');
      let adminToken = flag('--admin-token');
      let ca = flag('--ca');
      const guiUrl = flag('--gui-url');
      const code = flag('--code');
      const wantFp = flag('--ca-fingerprint');
      if (code) {
        // Another machine: trust the server's CA (fingerprint-checked), then
        // exchange the one-time code for the client token.
        if (server.startsWith('https:') && !ca) ca = await fetchCa(server, wantFp);
        const r = await backend.publicRequest(server, '/v1/pair/claim', { method: 'POST', body: { code, device: os.hostname() }, ca });
        token = r.token;
      }
      if (!token && !adminToken) {
        // Same machine: read the tokens the server generated.
        const dir = flag('--data') || process.env.SM_SERVER_DATA || path.join(ROOT, '.sm-server');
        const tokens = JSON.parse(fs.readFileSync(path.join(dir, 'tokens.json'), 'utf8'));
        token = tokens.client;
        adminToken = tokens.admin;
      }
      const cfg = { server, token, adminToken, ...(ca && { ca: path.resolve(ca) }), ...(guiUrl && { guiUrl }) };
      const who = await backend.request('/whoami', { cfg, admin: Boolean(adminToken) });
      backend.saveConfig(cfg);
      process.stderr.write(`smctl: logged in to ${server} (${who.scope}); config ${backend.configPath()}\n`);
      return 0;
    }
    case 'pair': {
      const r = await backend.request('/pair', { method: 'POST', admin: true });
      const cfg = backend.loadConfig();
      const lan = cfg.guiUrl || cfg.server;
      process.stdout.write(`Pairing code: ${r.code}   (single use, valid ${r.expiresInSeconds / 60} minutes)\n`);
      if (r.caFingerprint) process.stdout.write(`CA fingerprint: ${r.caFingerprint}\n`);
      process.stdout.write(`\nOn the other machine run:\n  ./installer.sh --client --server-url ${lan} --code ${r.code}\n` +
        `or, if sm is already installed there:\n  smctl login --server ${lan} --code ${r.code}${r.caFingerprint ? ` --ca-fingerprint ${r.caFingerprint}` : ''}\n`);
      return 0;
    }
    case 'logout':
      fs.rmSync(backend.configPath(), { force: true });
      process.stderr.write('smctl: logged out; sm now uses the local file store\n');
      return 0;
    case 'status': {
      const cfg = backend.loadConfig();
      if (!backend.usesServer(cfg)) {
        process.stdout.write('backend: local file store (not logged in to a server)\n');
        return 0;
      }
      process.stdout.write(`server:  ${cfg.server}\n`);
      try {
        const who = await backend.request('/whoami', { cfg });
        const { secrets } = await backend.request('/secrets', { cfg });
        process.stdout.write(`status:  ok (${who.scope} token), ${secrets.length} secret(s)\n`);
      } catch (err) {
        process.stdout.write(`status:  ${err.message}\n`);
        return 1;
      }
      return 0;
    }
    case 'gui': {
      const cfg = backend.loadConfig();
      if (!cfg.server || !cfg.adminToken) return fail('not logged in with an admin token (smctl login)');
      // The fragment (#...) is never sent to the server; the page moves it into session storage.
      const url = `${(rest.find((a) => /^https?:/.test(a)) || cfg.guiUrl || cfg.server).replace(/\/$/, '')}/#token=${encodeURIComponent(cfg.adminToken)}`;
      process.stdout.write(url + '\n');
      if (!rest.includes('--no-open')) {
        const opener = process.platform === 'darwin' ? 'open' : 'xdg-open';
        spawn(opener, [url], { stdio: 'ignore', detached: true }).on('error', () => {}).unref();
      }
      return 0;
    }
    case 'setup-code': {
      const { code, passwordSet } = await backend.request('/auth/setup-code', { admin: true });
      if (passwordSet) process.stdout.write('A GUI password is already set; use smctl passwd to change it.\n');
      else process.stdout.write(`${code}\nEnter this code with your new password on the GUI's first page (needed only from another machine).\n`);
      return 0;
    }
    case 'passwd': {
      let pw;
      if (process.stdin.isTTY) {
        pw = await readValue('new GUI password');
        const again = await readValue('repeat it');
        if (pw !== again) return fail('the passwords differ');
      } else {
        pw = await readValue('password');
      }
      await backend.request('/auth/password', { method: 'PUT', body: { password: pw }, admin: true });
      process.stderr.write('smctl: GUI password set; all GUI sessions were signed out\n');
      return 0;
    }
    case 'set': {
      const note = flag('--note');
      const category = flag('--category');
      const [name] = rest;
      if (!name || !NAME_RE.test(name)) return fail('usage: smctl set NAME [--note TEXT] [--category NAME]  (value on stdin)');
      const value = await readValue(name);
      if (!value) return fail('empty value');
      await backend.setSecret(name, value, note, category);
      if (value.length < 8) process.stderr.write(`smctl: warning: ${name} is short (${value.length} chars); redaction will also hit unrelated output that contains it\n`);
      process.stderr.write(`smctl: stored ${name}\n`);
      return 0;
    }
    case 'list': {
      const list = await backend.listSecrets();
      if (rest.includes('-l')) {
        for (const s of list) process.stdout.write(`${s.name.padEnd(24)} ${(s.category || '-').padEnd(14)} updated ${fmtTime(s.updatedAt)}  used ${s.uses ?? '-'}x  ${s.note || ''}\n`);
      } else {
        for (const s of list) process.stdout.write(s.name + '\n');
      }
      return 0;
    }
    case 'rotate': {
      const length = Number(flag('--length') || 12);
      const charset = flag('--charset') || 'alnum';
      if (!rest[0]) return fail('usage: smctl rotate NAME [--length N (12)] [--charset alnum|hex|base64url|symbols]');
      const r = await backend.rotateSecret(rest[0], length, charset);
      process.stderr.write(`smctl: ${rest[0]} rotated (${r.length} random ${charset} chars). Update anything that still uses the old value.\n`);
      return 0;
    }
    case 'rm':
      if (!rest[0]) return fail('usage: smctl rm NAME');
      return (await backend.removeSecret(rest[0])) ? 0 : fail(`no such secret: ${rest[0]}`);
    case 'env':
      for (const { name } of await backend.listSecrets()) process.stdout.write(`export ${name}='${placeholder(name)}'\n`);
      return 0;
    case 'audit':
      for (const e of await backend.readAudit(Number(rest[0] || 20))) process.stdout.write(JSON.stringify(e) + '\n');
      return 0;
    default:
      return fail('usage: smctl {login|logout|status|gui|pair|setup-code|passwd|set NAME|rotate NAME|list [-l]|rm NAME|env|audit [N]}');
  }
}

function fail(msg) {
  process.stderr.write(`smctl: ${msg}\n`);
  return 2;
}

main().then((code) => process.exit(code), (err) => { process.stderr.write(`smctl: ${err.message}\n`); process.exit(1); });
