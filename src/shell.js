// sm as a bash-compatible shell. Accepts bash's own arguments and runs the real
// bash with them, plus:
//   - every secret in the store is exported under its own name if that
//     variable is unset (so `$API_KEY` just works), and env values that contain
//     {{secret:NAME}} placeholders are substituted;
//   - {{secret:NAME}} inside a `-c` command string is rewritten to a variable
//     reference (see rewrite.js);
//   - stdout/stderr are redacted. Interactive mode runs bash on a pseudo
//     terminal through util-linux `script`, so line editing and prompts work.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { getSecrets, recordAudit } from './backend.js';
import { substitute, findNames } from './placeholders.js';
import { rewriteCommand, envName } from './rewrite.js';
import { Redactor } from './redactor.js';

const SELF = fs.realpathSync(fileURLToPath(new URL('../bin/sm.js', import.meta.url)));
const RCFILE = fileURLToPath(new URL('./sm-rc.bash', import.meta.url));
const AGENTS_FILE = fileURLToPath(new URL('./sm-agents.bash', import.meta.url));

function realShell() {
  const sh = process.env.SM_REAL_SHELL || '/bin/bash';
  try {
    if (fs.realpathSync(sh) === SELF) throw new Error(`SM_REAL_SHELL points at sm itself: ${sh}`);
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
    throw new Error(`real shell not found: ${sh}`);
  }
  return sh;
}

// Bash options that take a separate argument.
const OPT_WITH_ARG = new Set(['-o', '+o', '-O', '+O', '--rcfile', '--init-file']);

// Find the -c command string (index into args) and whether bash would read a
// script operand, following bash's argument rules closely enough.
export function parseArgs(args) {
  let hasC = false;
  let i = 0;
  for (; i < args.length; i++) {
    const a = args[i];
    if (a === '--' || a === '-') { i++; break; }
    if (OPT_WITH_ARG.has(a)) { i++; continue; }
    if (a.startsWith('--')) continue;
    if (/^[-+][A-Za-z]+$/.test(a)) {
      if (a[0] === '-' && a.includes('c')) hasC = true;
      // -o / -O may be combined at the end, e.g. -eo pipefail
      if (/[oO]$/.test(a) && a.length > 2) i++;
      continue;
    }
    break;
  }
  return { commandIndex: hasC && i < args.length ? i : -1, operandIndex: i < args.length ? i : -1, hasC };
}

export async function runShell(args) {
  let secrets = {};
  try {
    secrets = await getSecrets();
  } catch (err) {
    // An unreachable server must not break every command the agent runs.
    process.stderr.write(`sm: ${err.message}; running without secrets\n`);
  }
  const used = new Set();
  const sh = realShell();
  const { commandIndex, operandIndex, hasC } = parseArgs(args);

  const env = {};
  for (const [k, v] of Object.entries(process.env)) env[k] = substitute(v, secrets, used);
  if (process.env.SM_AUTO_ENV !== '0') {
    // The store is authoritative: a stored secret replaces an inherited variable
    // of the same name (e.g. a stale token still exported in an old shell).
    for (const [name, value] of Object.entries(secrets)) env[name] = value;
  }

  const outArgs = args.map((a, idx) => {
    if (idx === commandIndex) {
      return rewriteCommand(a, (name) => {
        if (!(name in secrets)) throw new Error(`unknown secret: ${name}`);
        used.add(name);
        env[envName(name)] = secrets[name];
      });
    }
    // Positional args after the command string ($0, $1, ...) and option
    // values: plain substitution.
    return substitute(a, secrets, used);
  });

  env.SM_ACTIVE = '1'; // lets scripts and prompts detect they run inside sm
  // Every variable that now holds a secret value, so agents started inside sm
  // can be given an environment without them (sm-agents.bash).
  const valueVars = new Set(Object.keys(env).filter((k) => k.startsWith('__SM_') && k !== '__SM_SECRET_VARS'));
  for (const [k, v] of Object.entries(env)) {
    if (k in secrets && v === secrets[k]) valueVars.add(k);
    if (process.env[k] !== undefined && process.env[k] !== v && findNames(process.env[k]).length) valueVars.add(k);
  }
  env.__SM_SECRET_VARS = [...valueVars].join(' ');
  if (process.env.BASH_ENV && process.env.BASH_ENV !== AGENTS_FILE) env.__SM_USER_BASH_ENV = process.env.BASH_ENV;
  env.BASH_ENV = AGENTS_FILE; // non-interactive bash (sm -c, scripts) loads the agent guard too
  const redactor = new Redactor(secrets);
  const interactive = !hasC && operandIndex === -1 && process.stdin.isTTY && process.stdout.isTTY;

  let child;
  if (interactive) {
    const q = (s) => `'${s.replace(/'/g, `'\\''`)}'`;
    const size = `stty rows ${process.stdout.rows || 24} cols ${process.stdout.columns || 80} 2>/dev/null; `;
    // Our rc file sources the usual ones and tags the prompt, unless the
    // caller chose its own rc setup.
    const ownRc = args.some((a) => a === '--norc' || a === '--rcfile' || a === '--init-file');
    const rc = ownRc ? [] : ['--rcfile', RCFILE];
    const inner = size + 'exec ' + [sh, ...rc, '-i', ...outArgs].map(q).join(' ');
    env.SHELL = sh; // programs that spawn $SHELL get bash, not a second sm layer
    child = spawn('script', ['-qfec', inner, '/dev/null'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
    process.stdin.setRawMode(true);
    process.stdin.pipe(child.stdin);
  } else {
    child = spawn(sh, outArgs, { env, stdio: ['inherit', 'pipe', 'pipe'] });
  }

  const forward = (sig) => () => child.kill(sig);
  const handlers = interactive ? {} : { SIGINT: forward('SIGINT'), SIGTERM: forward('SIGTERM'), SIGHUP: forward('SIGHUP') };
  for (const [sig, h] of Object.entries(handlers)) process.on(sig, h);

  const pipeDone = (src, dst) =>
    new Promise((resolve) => src.pipe(redactor.stream()).on('data', (d) => dst.write(d)).on('end', resolve));
  const outputs = Promise.all([pipeDone(child.stdout, process.stdout), pipeDone(child.stderr, process.stderr)]);

  return new Promise((resolve) => {
    let done = false;
    const finish = async (code) => {
      if (done) return;
      done = true;
      if (interactive) {
        process.stdin.unpipe(child.stdin);
        process.stdin.setRawMode(false);
        process.stdin.pause();
      }
      for (const [sig, h] of Object.entries(handlers)) process.off(sig, h);
      if (process.env.SM_AUDIT !== '0') {
        await recordAudit({
          mode: interactive ? 'interactive' : hasC ? 'command' : 'script',
          command: commandIndex >= 0 ? args[commandIndex] : args.join(' '), // as written: placeholders only
          placeholders: [...used],
          envPlaceholders: [...new Set(Object.values(process.env).flatMap(findNames))],
          redactions: redactor.counts,
          exit: code,
          cwd: process.cwd(),
        }).catch((err) => process.stderr.write(`sm: audit not recorded: ${err.message}\n`));
      }
      resolve(code);
    };
    child.on('error', (err) => {
      process.stderr.write(`sm: ${err.message}\n`);
      finish(127);
    });
    child.on('close', (code, signal) => outputs.then(() => finish(code ?? 128 + sigNum(signal))));
  });
}

const sigNum = (s) => ({ SIGHUP: 1, SIGINT: 2, SIGKILL: 9, SIGTERM: 15 })[s] ?? 1;
