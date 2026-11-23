# sm: secrets for AI agents, without showing them

`sm` lets AI coding agents (Claude Code, opencode, …) and you use API keys,
tokens and passwords in terminal commands **without the values ever appearing
in the agent's context**.

- **`sm`** is a drop-in replacement for `bash`. Inside it every secret is an
  environment variable (`$GITHUB_TOKEN`), and any secret that shows up in the
  output is replaced by **`[BLOCKED:NAME]`**.
- **`sm-server`** keeps the secrets encrypted and serves a web **GUI** to manage
  them. Other machines on your network can use the same server.
- An **agent skill** teaches Claude Code and opencode to work this way:
  `sm -c '…'` for commands, `sm-ls` / `sm-add` for secrets, and reading `.env`
  files or logs through `sm`.

```console
$ sm -c 'curl -s -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user | head -3'
{
  "login": "you",
$ sm -c 'echo "$GITHUB_TOKEN"'
[BLOCKED:GITHUB_TOKEN]
```

**Scope:** sm protects against *accidental* leaks: a debug print, `env`, a
verbose `curl`, a config file or a log read into the agent's context. It does
not stop an agent that deliberately tries to extract a value (see
[Security model](#security-model)).

Requirements: Linux, Node.js 20+, bash, util-linux `script` (interactive shell),
`openssl` only if the installer should generate certificates.

---

## Contents

- [Quick start](#quick-start)
- [Installer](#installer)
- [Using `sm`](#using-sm)
- [Managing secrets](#managing-secrets): [GUI](#gui) · [command line](#command-line-reference)
- [Other machines](#using-the-server-from-other-machines)
- [Syncing several servers (sm-vault)](#syncing-several-servers-sm-vault)
- [GitHub (git and gh)](#github-git-and-gh)
- [AI agents](#ai-agents)
- [Security model](#security-model)
- [Configuration reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)
- [Uninstall](#uninstall)
- [Development](#development)

---

## Quick start

```bash
git clone https://github.com/lethevimlet/secret-manager && cd secret-manager
./installer.sh                 # answer "y" to run the server on this machine
```

Then:

1. Open the GUI the installer printed (e.g. `https://192.168.1.10:8737`) and
   **set a password** on the first visit.
2. Add a secret, in the GUI (**Add secret**) or from a terminal:

   ```bash
   printf %s 'the-real-value' | smctl set OPENAI_API_KEY --category AI --note "OpenAI, personal"
   ```

3. Use it:

   ```bash
   sm -c 'curl -s https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY" | head'
   ```

---

## Installer

```bash
./installer.sh            # interactive
```

What it does, in order:

1. **Commands.** Checks Node 20+, runs `npm ci` if needed, and installs `sm`,
   `smctl`, `sm-ls`, `sm-add`, `sm-server` and `git-credential-sm` into
   `/usr/local/bin` (as root) or `~/.local/bin`. They're small wrappers with
   the absolute `node` path, so they also work in systemd units and in shells
   where `node` isn't on the `PATH` (nvm).
2. **"Run the sm server on THIS machine?"**
   - **Yes → server mode.** Asks whether to also serve the GUI on your network
     over HTTPS. For that it needs an IP address and either your own
     certificate (cert, key and optionally the CA that signed it) or it
     **generates a local CA and a certificate** (in `.sm-server/tls/`). It then
     writes a systemd unit **enabled at boot** (`/etc/systemd/system/sm-server.service`
     as root; a user unit otherwise, plus `loginctl enable-linger`), starts it,
     waits until it answers and logs the CLI in. An existing unit is backed up
     first.
   - **No → client mode.** Asks for the URL of an existing server and a
     **pairing code** (see [other machines](#using-the-server-from-other-machines)).
3. **Agent skill** for Claude Code and opencode (symlinks into
   `~/.claude/skills` and `~/.config/opencode/skills`), and optionally the
   start-of-conversation announcement in `~/.claude/CLAUDE.md` and
   `~/.config/opencode/AGENTS.md`.
4. **GitHub**: let git get the token from sm (see [GitHub](#github-git-and-gh)).

It's safe to run again (e.g. after `git pull`, or to change the LAN address).

### Installer options

| Option | Meaning |
|---|---|
| `--server` | Server mode without asking. |
| `--lan IP` | Also serve HTTPS on this address (server mode). |
| `--tls-cert F --tls-key F [--tls-ca F]` | Use your own certificate. `--tls-ca` lets other machines download and trust the CA. |
| `--gen-tls` | Generate a local CA and a certificate for `--lan`. |
| `--sync-interval MIN` | Minutes between vault syncs (default 5; a re-install keeps the current value). |
| `--port N` | Port (default 8737). |
| `--no-service` | Don't install the systemd unit; just print it. |
| `--client` | Client mode without asking. |
| `--server-url URL --code CODE` | Server to pair with and the code from `smctl pair`. |
| `--ca-fingerprint FP` | Expected CA fingerprint (needed when not interactive). |
| `--bin DIR` | Where to put the commands. |
| `--no-skill`, `--no-git` | Skip those steps. |
| `--yes`, `-y` | Accept defaults, ask nothing. |

Examples:

```bash
# A server that also serves the GUI on the LAN, with its own generated CA
./installer.sh --server --lan 192.168.1.10 --gen-tls --yes

# The same with an existing certificate
./installer.sh --server --lan 192.168.1.10 --tls-cert server.crt --tls-key server.key --tls-ca ca.crt

# A laptop using that server (code from `smctl pair` on the server)
./installer.sh --client --server-url https://192.168.1.10:8737 --code ABCD-EFGH
```

---

## Using `sm`

`sm` takes the same arguments as bash:

```bash
sm -c 'command …'          # one command (use single quotes, see below)
sm ./script.sh arg1 arg2    # a script
echo 'env | sort' | sm      # commands on stdin
sm                          # interactive shell, prompt tagged with a red "sm"
```

Inside `sm`:

- **Every secret is an environment variable with its own name**, replacing any
  variable of that name the shell already had. Write
  `$NAME` in the command. Use **single quotes** around `-c '…'` so `$NAME` is
  expanded inside sm (where it exists), not by your current shell (where it's
  empty).
- **`{{secret:NAME}}` placeholders** also work in a `-c` command and are safe
  in any quoting: `sm -c "curl -H 'X-Api-Key: {{secret:API_KEY}}' …"`. An
  unknown name stops the command before anything runs.
- **Output is filtered.** Every known secret in stdout and stderr becomes
  `[BLOCKED:NAME]`, also when it appears hex-, base64-, URL- or JSON-encoded.
- `SM_ACTIVE=1` is set, so scripts can tell they run inside sm.
- Exit codes are passed through. If the server is unreachable, commands still
  run, without secrets, and sm prints a warning.

Reading files or logs that may contain secrets works the same way and is safe
to show to an agent:

```bash
sm -c 'cat .env'
sm -c 'journalctl -u myapp -n 100 --no-pager'
sm -c 'docker inspect api'
```

**In systemd units**, run the command through sm and reference secrets by
name, either directly as `$NAME` or as a placeholder in another variable:

```ini
[Service]
Environment=API_AUTH=Bearer {{secret:MY_API_KEY}}
ExecStart=/usr/local/bin/sm /opt/myjob/run.sh
```

---

## Managing secrets

### GUI

Open the server's address in a browser (`smctl gui` prints it, signed in).

- **First visit:** set a password (at least 10 characters). It's stored only as
  a salted scrypt hash. From another machine this first setup also needs a
  one-time **setup code**: run `smctl setup-code` on the server. That way
  nobody else on your network can claim the server before you.
- **Sign in** with that password. Sessions last 12 hours; a server restart
  signs everyone out. After 5 wrong passwords from an address, each further
  try has to wait longer. **Password** (top bar) changes it; `smctl passwd`
  resets a forgotten one.
- **Secrets tab**
  - **Add secret:** name (= the variable name), value or **Generate a random
    value**, category, note.
  - **Show:** displays a value for 30 seconds with **Copy**. Every view is
    logged.
  - **Rotate:** replaces the value with a new random one generated on the
    server (length and characters selectable, default 12 letters and digits).
    The new value is shown with a **Copy** button. Use it for values *you*
    control (your own app's signing key, a database password you'll update).
    For keys issued by a service (GitHub, OpenAI …) use **Replace value** with
    the new key from that service.
  - **Edit** (category and note), **Replace value**, **Delete**.
  - **Categories** split the list into sections and show as filter chips;
    **search** covers name, category and note (press `/`).
- **Activity tab:** every command run through `sm` (as written, with
  placeholders), value fetches, views, changes, sign-ins and pairings. Never a
  value. Kept 30 days or 10,000 entries.

### Command line reference

**Using secrets** (needs the client token; works on paired machines):

| Command | What it does |
|---|---|
| `sm -c '…'`, `sm script`, `sm` | Run with secrets as variables, output blocked. |
| `sm-ls [SEARCH] [-q] [--json]` | List names, categories and notes. Never values. |
| `sm-add NAME --generate [N] [--charset C] [--category X] [--note T]` | Create a secret with a random value (default 12 chars). |
| `COMMAND \| sm-add NAME …` | Create a secret from a command's output without displaying it. |
| `sm-add … --if-missing` | Do nothing (exit 0) if the name exists. |

`sm-add` **only creates**: an existing name is refused (exit 3), and a value
given as an argument is refused (it would show up in `ps`, the shell history
and an agent's transcript). Character sets: `alnum` (default), `hex`,
`base64url`, `symbols`.

**Administration** with `smctl` (needs the admin token, i.e. on the server):

| Command | What it does |
|---|---|
| `smctl status` | Which server, whether it answers, how many secrets. |
| `smctl gui [URL] [--no-open]` | Print/open the GUI address, already signed in. |
| `printf %s VALUE \| smctl set NAME [--category X] [--note T]` | Add or replace a value (from stdin). |
| `smctl rotate NAME [--length N] [--charset C]` | New random value, generated on the server. |
| `smctl list [-l]` | Names (with `-l`: category, dates, use count, note). |
| `smctl rm NAME` | Delete a secret. |
| `smctl audit [N]` | Last N activity entries. |
| `smctl env` | Print `export NAME='{{secret:NAME}}'` lines. |
| `smctl sync [status]` | Vault state: repository, last sync, last error. |
| `smctl sync deploy-key` | This server's SSH key, to add to the vault repository. |
| `smctl sync init --repo URL [--out FILE]` | First server: create the vault, write `sm-vault.key`. |
| `smctl sync join --key-file FILE` | Another server: join with the key file and its password. |
| `smctl sync now` | Sync immediately. |
| `smctl sync key-file [--out FILE]` | A fresh key file, locked with the current GUI password. |
| `smctl pair` | One-time code for another machine. |
| `smctl setup-code` | Code for setting the first GUI password from another machine. |
| `smctl passwd` | Set or reset the GUI password. |
| `smctl login [...]`, `smctl logout` | Connect the CLI to a server; logout = local file store. |

---

## Using the server from other machines

1. **On the server:**

   ```console
   $ smctl pair
   Pairing code: ABCD-EFGH   (single use, valid 10 minutes)
   CA fingerprint: 73:4E:57:…:C5:AF

   On the other machine run:
     ./installer.sh --client --server-url https://192.168.1.10:8737 --code ABCD-EFGH
   ```

2. **On the other machine:** clone the repo and run that command. If sm is
   already installed there:
   `smctl login --server https://192.168.1.10:8737 --code ABCD-EFGH`.
   It downloads the server's CA certificate from `/ca.pem`, shows its
   fingerprint and asks you to compare it with the one `smctl pair` printed
   (or checks `--ca-fingerprint`), then exchanges the code for the token.

That machine gets the **client** token: it can use secrets (`sm -c`, `sm-ls`)
and create new ones (`sm-add`), but cannot view, replace or delete them. Wrong
codes are rate-limited; each pairing appears in Activity with the machine's
name. The server must serve HTTPS on the network (`--lan`) and publish its CA
(`--gen-tls` or `--tls-ca`); otherwise copy the CA certificate over and add
`--ca /path/ca.crt` to `smctl login`.

---

## Syncing several servers (sm-vault)

Pairing (above) is enough for machines that can reach the server. When a
machine needs **its own** server (away from home, or so secrets keep working
while this one is off), several servers can share their secrets through a
private git repository, e.g. `sm-vault` on GitHub.

**What is where**

- **The repository** holds only ciphertext: one AES-256-GCM file per secret,
  named by a keyed hash of the secret's name. GitHub sees neither names nor
  values, only how many secrets there are and when they change.
- **The vault key** (random, 256 bits) is never in the repository. It is in
  the **key file** `sm-vault.key`, locked with your GUI password (scrypt). A
  leaked repository alone can't be attacked by guessing passwords: there is
  nothing in it to test a guess against. You need the key file **and** the
  password.
- **Each server** unlocks the key file once, when it joins, and then keeps the
  vault key in its data folder (sealed with its `master.key`), so it starts
  and syncs unattended. Changing a server's GUI password later doesn't affect
  the key file; `smctl sync key-file` makes a fresh copy with the current one.
- **Synced:** values, categories, notes, deletions. **Per server:** GUI
  password, tokens, pairings, Activity.

> **Keep one copy of `sm-vault.key` offline** (password manager, USB stick).
> If every copy is lost, nobody, you included, can decrypt the repository.

**Set up** (GUI: **Sync** tab; or the commands below)

1. Create an empty **private** repository, e.g. `sm-vault` (no README or
   licence, so it stays empty).
2. On each server, get its deploy key (GUI: *Show this server's deploy key*):

   ```bash
   smctl sync deploy-key
   ```

   It prints one line like `ssh-ed25519 AAAAC3Nz… sm-vault@code`. In the
   repository open *Settings › Deploy keys › Add deploy key*, give it a title
   (e.g. the server's name), paste **the whole line** (key type, key and the
   `sm-vault@…` label) and tick **Allow write access**: without it the server
   can read but not upload. Every server has its own key, so one machine can
   be revoked without touching the others. This is the public half; the
   private half never leaves the server.

3. **First server:** create the vault. Every secret on this server is
   uploaded, and `sm-vault.key` is written (asks for the GUI password).

   ```bash
   smctl sync init --repo git@github.com:you/sm-vault.git
   ```

   Deploy keys work over SSH only; the `https://github.com/you/sm-vault`
   address GitHub shows by default is accepted and converted. In the GUI the
   key file is downloaded by the browser. Keep it, plus one copy offline.

4. **Every other server:** copy `sm-vault.key` over and join (asks for the
   password the key file was made with). Secrets from the vault are added;
   secrets only this server has are uploaded. A brand-new server without a GUI
   password takes this password as its GUI password.

   ```bash
   smctl sync join --key-file sm-vault.key
   ```

**Checking it.** The Sync tab opens with one state and a sentence, e.g.
**✓ In sync**: *All 16 secrets on this server are in the vault*, with the last
and next sync. Below it: secrets here, secrets in the vault (as counted at the
last sync, deletions not counted), and what the last sync changed. Other
states: **Changes pending** (changed here, uploaded within seconds), **Not in
sync** (counts differ: press *Sync now*, then check Activity) and **Sync
failed** (with git's message). `smctl sync` prints the same:

```
repo:       git@github.com:you/sm-vault.git
device:     code
last sync:  2026-11-23 02:39:51  (pulled 0, pushed 0, conflicts 0)
secrets:    16 here, 16 in the vault  (in sync)
```

A sync that reports *0 from the vault, 0 to it* is normal: nothing had
changed. The first sync after `init` uploads everything.

**How syncing works.** Each server pulls and pushes every 5 minutes
(`SM_VAULT_INTERVAL` in seconds, or `installer.sh --sync-interval MIN`) and a
few seconds after any change here, so the interval only decides how quickly
*other* servers' changes arrive. The traffic is small: one `git fetch` per
interval, a push only when something changed. Per secret, the newer change
wins; when the same secret was changed on two servers since the
last sync, Activity shows a **sync conflict** naming which server's version was
kept. Deletions are remembered, so a server that was offline does not bring a
deleted secret back; re-creating the secret later is a newer change and syncs
normally. `smctl sync` shows the state, `smctl sync now` syncs immediately.

**Trade-offs.** Every server holds every secret: a compromised server exposes
all of them, as with one server today. The repository's history (ciphertext)
stays on the git host for good.

---

## GitHub (git and gh)

Store the token once under the name **`GITHUB_TOKEN`**:

```bash
printf %s "$TOKEN" | sm-add GITHUB_TOKEN --category GitHub
```

The installer (step 4) makes git ask `git-credential-sm` for github.com. That
helper answers **only inside sm**, so:

```bash
sm -c 'git push'               # pull, fetch, clone of private repos too
sm -c 'gh pr create --fill'    # gh reads GITHUB_TOKEN by itself
```

A plain `git push` stops with *"credentials are only available inside sm"*.
Remote URLs stay token-free (`https://github.com/owner/repo.git`). Don't put a
token into a remote URL, `.git/config`, `~/.bashrc` or a script.

Manual setup, if you skipped the installer step:

```bash
git config --global credential.https://github.com.helper ''
git config --global --add credential.https://github.com.helper '!node /path/to/secret-manager/bin/git-credential-sm.js'
```

---

## AI agents

### The skill

`skills/secret-manager/SKILL.md` is installed for Claude Code and opencode by
the installer (as symlinks, so a `git pull` updates it). It tells agents to:

- find secrets with `sm-ls` and use them as `$NAME` inside `sm -c '…'`;
- create missing ones with `sm-add --generate` or a pipe, reuse existing ones,
  and ask you for keys only you have (never to paste them into the chat);
- read anything that might contain a secret (`.env`, configs, logs, env dumps,
  `docker inspect`, `git diff`) through `sm`, never with their own file reader;
- run `git` and `gh` through `sm`;
- never print, decode, copy or send a value, and never call the server's API.

With the global instructions (installer step 3), agents start every
conversation with:

> 🔒 Using **secret-manager**: secrets stay in sm. I only use them by name
> through `sm`, read anything that may contain one through `sm`, and will
> never reveal, copy or exfiltrate a secret value.

If an agent ignores the skill, nothing leaks: plain commands simply don't have
the secrets and fail (e.g. with 401).

### Never start an agent inside `sm`

Inside sm every secret is a real environment variable. An agent started there
would inherit them all and send its commands' output to the model **through
its own connection**, which sm cannot filter: only *your terminal* shows
`[BLOCKED]`. So in `sm` shells, `claude`, `opencode`, `codex`, `aider`,
`gemini` and `cursor-agent` start with every secret removed (with a red note).
Starting an agent by its full path bypasses this: don't.

### Optional: sm as the agent's shell

Instead of relying on the skill, Claude Code can run *every* command through
sm. It only accepts a shell named `bash`:

```bash
mkdir -p ~/.local/share/sm/bin && ln -sf "$(command -v sm)" ~/.local/share/sm/bin/bash
CLAUDE_CODE_SHELL=~/.local/share/sm/bin/bash claude
```

The downside is that every command, even `ls`, then has every secret in its
environment.

---

## Security model

**Where things live (server):** `.sm-server/` (folder 0700, files 0600)

| File | Contents |
|---|---|
| `secrets.json` | Values encrypted with AES-256-GCM (random IV, bound to the name), plus metadata. |
| `master.key` | Encryption key (or `SM_MASTER_KEY`). Next to the data, so it protects a *copied* `secrets.json`, not the machine. |
| `tokens.json` | Admin (`sma_…`) and client (`smc_…`) tokens. |
| `auth.json` | GUI password as a scrypt hash. |
| `audit.log` | Activity, never values. |

**Access**

| Who | Can |
|---|---|
| GUI (password) / admin token (`smctl` on the server) | Everything: add, replace, rotate, delete, view values, activity, pairing. |
| Client token (`sm`, `sm-ls`, `sm-add`, paired machines) | Fetch values for `sm`, list names, create new secrets. |
| No token | `/health`, `/ca.pem`, sign-in and pairing endpoints only. |

Plain HTTP is served only on `127.0.0.1`; on the network only HTTPS.

**What the output filter catches:** raw values, hex (both cases), base64 and
base64url (also inside larger data, at any offset), URL encoding, JSON
escaping, and secrets split across output chunks arriving within 150 ms.

**What it does not stop** (deliberate extraction):

- transformations: `rev`, spaced letters, xor, compression, arithmetic …;
- one character per command, yes/no questions, exit codes;
- writing a value to a file, git or the network and reading it elsewhere;
- anything running as the same user reading `~/.config/sm/config.json` (the
  tokens) or `/proc/<pid>/environ` of a running command;
- an agent started inside sm by its full path.

Stopping those would need a boundary the agent can't cross (a sandbox, plus a
broker or proxy that holds the secrets). `npm run demo` shows a leak matrix of
what is and isn't caught.

---

## Configuration reference

**Server** (`sm-server`, usually set in the systemd unit)

| Variable | Default | Meaning |
|---|---|---|
| `SM_PORT` | `8737` | Port of the local HTTP listener. |
| `SM_BIND` | `127.0.0.1` | Address of that listener (plain HTTP only on loopback). |
| `SM_LAN_BIND` | (none) | Extra HTTPS listener on this address. |
| `SM_LAN_PORT` | `SM_PORT` | Its port. |
| `SM_TLS_CERT`, `SM_TLS_KEY` | (none) | Certificate and key for HTTPS. |
| `SM_TLS_CA` | (none) | CA certificate, served at `/ca.pem` for other machines. |
| `SM_SERVER_DATA` | `.sm-server/` | Data folder. |
| `SM_MASTER_KEY` | key file | 64 hex characters instead of `master.key`. |
| `SM_AUDIT_DAYS`, `SM_AUDIT_MAX` | `30`, `10000` | Activity retention (0 = no limit). |
| `SM_DEVICE` | hostname | This server's name in the vault (shown in conflicts and commits). |
| `SM_VAULT_INTERVAL` | `300` | Seconds between vault syncs. |
| `SM_NO_AUTH=1` | off | **Testing only:** GUI without password (viewing values still needs the admin token). |

**Client** (`sm`, `smctl`, `sm-ls`, `sm-add`)

| Variable | Meaning |
|---|---|
| `SM_CONFIG` | Config file (default `~/.config/sm/config.json`, written by `smctl login`). |
| `SM_SERVER`, `SM_TOKEN`, `SM_ADMIN_TOKEN` | Override server URL and tokens. |
| `SM_BACKEND=file` | Use the local file store (`.sm/`) instead of a server. |
| `SM_AUTO_ENV=0` | Don't export secrets as `$NAME` (only placeholders in env/command are resolved). |
| `SM_PROMPT` | Prompt tag of interactive shells (`SM_PROMPT=` turns it off). |
| `SM_AUDIT=0` | Don't report commands to Activity. |
| `SM_GIT_SECRET` | Secret name `git-credential-sm` uses (default `GITHUB_TOKEN`). |

---

## Troubleshooting

| Message | What to do |
|---|---|
| `sm: unknown secret: NAME` | No secret with that name: `sm-ls`. |
| `sm: secret server … unreachable; running without secrets` | Server down: `systemctl status sm-server`, `smctl status`. |
| `git-credential-sm: github.com credentials are only available inside sm` | Run it as `sm -c 'git push'`. |
| `sm-add: NAME already exists` (exit 3) | Use the existing secret, or replace it in the GUI. |
| `wrong or expired pairing code` | Codes are single use and last 10 minutes: run `smctl pair` again. |
| `CA fingerprint mismatch` | You're not talking to your server, or it has a new certificate: compare with `smctl pair`. |
| Variable is empty inside `sm -c "…"` | Use single quotes: `sm -c '… $NAME …'`. |
| Sync: *"deploy keys don't work over HTTPS"* / *"could not read Username"* | Use the SSH address `git@github.com:you/sm-vault.git` (current versions convert `https://github.com/…` themselves). |
| Sync: *"can't reach the repository"* / `Permission denied (publickey)` | Add the server's deploy key (`smctl sync deploy-key`) to that repository. |
| Sync: *"the deploy key has no write access"* | Tick *Allow write access* on the deploy key in the repository settings. |
| Sync: *"wrong password for this key file"* | Use the password the key file was made with (the GUI password at the time of `init` or `key-file`). |
| Sync: *"this key file belongs to a different vault"* | The key file is from another vault repository: use the one made for this repository. |
| GUI says *"value must be a non-empty string"* right after an update | The browser has new files but the server still runs old code: `systemctl restart sm-server`. |

---

## Uninstall

```bash
sudo systemctl disable --now sm-server && sudo rm /etc/systemd/system/sm-server.service   # or ~/.config/systemd/user/
rm /usr/local/bin/{sm,smctl,sm-ls,sm-add,sm-server,git-credential-sm}                     # or ~/.local/bin/
rm ~/.claude/skills/secret-manager ~/.config/opencode/skills/secret-manager
cp ~/.gitconfig.before-sm ~/.gitconfig          # restores the previous git credential helper
# remove the "secret-manager (sm)" block from ~/.claude/CLAUDE.md and ~/.config/opencode/AGENTS.md
# the data (.sm-server/) and ~/.config/sm/ are left in place: delete them when you're sure
```

---

## Development

```bash
npm test        # 39 tests: output filter, quoting, shell, agent guard, git helper, server API
npm run demo    # leak matrix against a throwaway store
npm run server  # run the server in the foreground
```

| Path | |
|---|---|
| `bin/sm.js` | The shell (`src/shell.js`): substitution, filter, audit. |
| `bin/smctl.js`, `bin/sm-ls.js`, `bin/sm-add.js` | CLI. |
| `bin/git-credential-sm.js` | git credential helper. |
| `src/redactor.js` | Streaming output filter. |
| `src/rewrite.js` | `{{secret:NAME}}` → quoted variable references. |
| `src/sm-rc.bash`, `src/sm-agents.bash` | Interactive prompt; agent guard. |
| `server/` | API (`app.js`), encrypted store, GUI sign-in (`auth.js`), web GUI (`public/`). |
| `skills/` | Agent skill and global instructions. |
| `installer.sh` | Installer. |

---

## License

[MIT](LICENSE)
