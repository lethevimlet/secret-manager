// Where sm keeps its data. Outside the package folder, so an npm update
// (which replaces that folder) never touches secrets or keys.
//   server data:  $SM_SERVER_DATA, else ~/.local/share/sm/server
//   local store:  $SM_HOME,        else ~/.local/share/sm/local  (SM_BACKEND=file)
// Older installs kept them inside the project folder (.sm-server/, .sm/);
// those are still used when they exist.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const PKG_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export function dataHome() {
  const xdg = process.env.XDG_DATA_HOME;
  return path.join(xdg && path.isAbsolute(xdg) ? xdg : path.join(os.homedir(), '.local', 'share'), 'sm');
}

function pick(envValue, legacy, fresh) {
  if (envValue) return envValue;
  if (fs.existsSync(legacy)) return legacy;
  return fresh;
}

export function serverDataDir() {
  return pick(process.env.SM_SERVER_DATA, path.join(PKG_DIR, '.sm-server'), path.join(dataHome(), 'server'));
}

export function localStoreDir() {
  return pick(process.env.SM_HOME, path.join(PKG_DIR, '.sm'), path.join(dataHome(), 'local'));
}
