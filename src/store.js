// Mock secret store for the prototype: a plain JSON file (mode 0600).
// In the real design this is replaced by the remote endpoint / broker.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const PKG_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function storeDir() {
  return process.env.SM_HOME || path.join(PKG_DIR, '.sm');
}

function storeFile() {
  return path.join(storeDir(), 'secrets.json');
}

export function loadSecrets() {
  try {
    return JSON.parse(fs.readFileSync(storeFile(), 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    throw err;
  }
}

function saveSecrets(secrets) {
  fs.mkdirSync(storeDir(), { recursive: true, mode: 0o700 });
  const tmp = storeFile() + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(secrets, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, storeFile());
}

export function setSecret(name, value) {
  if (!NAME_RE.test(name)) throw new Error(`invalid secret name: ${name}`);
  if (!value) throw new Error('empty value');
  const secrets = loadSecrets();
  secrets[name] = value;
  saveSecrets(secrets);
}

export function removeSecret(name) {
  const secrets = loadSecrets();
  if (!(name in secrets)) return false;
  delete secrets[name];
  saveSecrets(secrets);
  return true;
}

export function auditFile() {
  return path.join(storeDir(), 'audit.log');
}

export function audit(entry) {
  fs.mkdirSync(storeDir(), { recursive: true, mode: 0o700 });
  fs.appendFileSync(auditFile(), JSON.stringify({ time: new Date().toISOString(), ...entry }) + '\n', { mode: 0o600 });
}
