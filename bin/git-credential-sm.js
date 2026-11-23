#!/usr/bin/env node
// git-credential-sm: git credential helper that answers only inside sm.
//
// Configure (global):
//   git config --global credential.https://github.com.helper ''
//   git config --global --add credential.https://github.com.helper '!node /path/to/bin/git-credential-sm.js'
//
// On `get` for a known host it returns the token from the environment
// variable sm injects (GITHUB_TOKEN for github.com). Outside sm that variable
// doesn't exist, so it answers nothing and tells git to stop (quit=1):
// `git push` then fails with a hint to run it as `sm -c 'git push'`. It never
// asks the sm server itself, so setting SM_ACTIVE=1 by hand gets nothing.
import fs from 'node:fs';

const HOSTS = {
  'github.com': 'GITHUB_TOKEN',
  'gist.github.com': 'GITHUB_TOKEN',
};

const op = process.argv[2];
if (op !== 'get') process.exit(0); // store/erase: nothing to do, sm owns the value

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (d) => (input += d));
process.stdin.on('end', () => {
  const req = Object.fromEntries(
    input.split('\n').filter((l) => l.includes('=')).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
  );
  if (req.protocol !== 'https' || !HOSTS[req.host]) return; // not ours: let other helpers answer
  const name = process.env.SM_GIT_SECRET || HOSTS[req.host];
  const token = process.env[name];
  if (process.env.SM_ACTIVE !== '1' || !token || token.startsWith('{{secret:')) {
    process.stderr.write(
      `git-credential-sm: ${req.host} credentials are only available inside sm.\n` +
      `  run:  sm -c 'git ${process.env.GIT_SM_HINT || 'push'}'   (or use an interactive sm shell)\n`,
    );
    process.stdout.write('quit=1\n');
    return;
  }
  process.stdout.write(`username=x-access-token\npassword=${token}\n`);
  // Tell sm the secret was used (counts in "Last used" / "Uses").
  if (process.env.SM_USAGE_FILE) {
    try { fs.appendFileSync(process.env.SM_USAGE_FILE, name + '\n'); } catch {}
  }
});
