#!/usr/bin/env node
// smctl: manage secrets (on the sm-server once logged in, else the local file store).
//   smctl login [--server URL] [--data DIR] [--token T --admin-token A] [--ca PEM] [--gui-url URL]
//   smctl status
//   smctl gui [URL] [--no-open]   print (and try to open) the GUI URL, signed in
//   smctl setup-code          one-time code to set the first GUI password from another machine
//   smctl passwd              set/reset the GUI password (admin token; new password on stdin or prompted)
//   smctl set NAME [--note TEXT] [--category NAME]   value from stdin (never argv)
//   smctl list                names only
//   smctl rm NAME
//   smctl env                 `export NAME='{{secret:NAME}}'` lines
//   smctl audit [N]
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
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

const fmtTime = (iso) => (iso ? iso.replace('T', ' ').slice(0, 19) : '-');

async function main() {
  switch (command) {
    case 'login': {
      const server = flag('--server') || DEFAULT_SERVER;
      let token = flag('--token');
      let adminToken = flag('--admin-token');
      const ca = flag('--ca');
      const guiUrl = flag('--gui-url');
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
      return fail('usage: smctl {login|logout|status|gui|setup-code|passwd|set NAME|list [-l]|rm NAME|env|audit [N]}');
  }
}

function fail(msg) {
  process.stderr.write(`smctl: ${msg}\n`);
  return 2;
}

main().then((code) => process.exit(code), (err) => { process.stderr.write(`smctl: ${err.message}\n`); process.exit(1); });
