# sm-proto: a bash-compatible shell that hides secrets (prototype)

`sm` is a drop-in replacement for `bash`. It runs the real bash with the same
arguments, but:

- every secret in the store is available as `$NAME` inside the shell, and
  `{{secret:NAME}}` placeholders in a `-c` command are resolved;
- secrets in stdout and stderr are replaced by `[BLOCKED:NAME]` before they reach whoever called the shell
  (a terminal, or an AI agent's tool result).

The calling process (the agent) never has the values in its own environment.

**Scope: accidental leaks only.** See "What it does not stop".

Node >= 20, Linux (interactive mode uses util-linux `script`). The server uses Express.

## Server + GUI

`sm-server` keeps the secrets (AES-256-GCM per value) and serves a web GUI.
`sm` fetches values from it for every command; `smctl` and the GUI manage it.

Run as a service that starts at boot (example unit, adjust paths):

```ini
# /etc/systemd/system/sm-server.service
[Service]
WorkingDirectory=/path/to/secret-manager
ExecStart=/path/to/node server/index.js
Environment=SM_LAN_BIND=192.168.1.10 SM_TLS_CERT=/path/server.crt SM_TLS_KEY=/path/server.key
Restart=on-failure
[Install]
WantedBy=multi-user.target
```

```bash
npm run server             # http://127.0.0.1:8737, data in .sm-server/
smctl login                # same machine: reads .sm-server/tokens.json
smctl gui                  # prints/opens the GUI URL, already signed in
smctl status
```

- **GUI password**: on the first visit the GUI asks you to set one (at least 10
  characters). It is stored only as a salted scrypt hash (`.sm-server/auth.json`,
  0600). From another machine the first setup also needs a one-time code from
  `smctl setup-code` (so nobody else on the LAN can claim the server first).
  Signing in gives an HttpOnly, SameSite=Strict session cookie (12 h; a server
  restart signs everyone out); changes made with it need an `X-SM-GUI` header
  (CSRF guard); 5 wrong passwords from an IP start an increasing wait.
  Change it in the GUI (Password), reset a forgotten one with `smctl passwd`.
- **Admin token** (`sma_…`): add, replace, delete, view values, read the activity
  log. Used by the GUI and `smctl`. Viewing a value (GUI "Show") always needs
  this token, even with `SM_NO_AUTH=1`; each view is logged with the client IP,
  and the value hides again after 30 s or when the browser tab is hidden.
- **Client token** (`smc_…`): what `sm` uses to fetch values and report the
  commands it ran.
- Plain HTTP only on localhost. For the LAN add an HTTPS listener with
  `SM_LAN_BIND=192.168.1.10 SM_TLS_CERT=… SM_TLS_KEY=…` (the loopback HTTP
  listener stays for local clients); plain HTTP on other addresses is refused.
- Remote clients: `smctl login --server https://HOST:8737 --token … --admin-token … --ca ca.crt`.
- `smctl login --gui-url https://HOST:8737` makes `smctl gui` print the LAN address.
- If the server is down, `sm` still runs commands, without secrets, and warns.
- **Rotate** (GUI row button, or `smctl rotate NAME [--length N] [--charset alnum|hex|base64url|symbols]`, default 12 characters)
  replaces a value with a random one generated on the server; the Add form can
  generate one too. The GUI shows the new value right away so you can update
  whatever uses it. Category and note are kept; Activity logs length and charset.
- Secrets can have a category (`smctl set NAME --category GitHub`, or the GUI).
  The GUI groups the list by category, filters with category chips and
  searches name, category and note (press `/`).
- `smctl logout` switches `sm` back to the local file store.
- The master key sits next to the data (`.sm-server/master.key`), so the
  encryption only protects a copied `secrets.json`, not a same-user attacker.

## Try it

```bash
cd /path/to/secret-manager
npm link                                             # puts sm, smctl, sm-server on PATH
printf %s 'sk-test-abcdef123456' | smctl set API_KEY   # value via stdin, never argv
smctl list -l                                        # names and metadata only

sm -c 'echo "$API_KEY"'                  # -> [BLOCKED:API_KEY]
sm -c 'echo {{secret:API_KEY}}'          # -> [BLOCKED:API_KEY]
sm -c '[ ${#API_KEY} = 20 ] && echo the program sees the real value'
sm                                       # interactive shell, output redacted
smctl audit                              # what ran, placeholders only
```

Interactive `sm` shells load your normal `~/.bashrc` and prefix the prompt with a
red `sm ` tag (`SM_PROMPT='[sm] '` to change it, `SM_PROMPT=` to turn it off).
`SM_ACTIVE=1` is set inside every `sm` shell.

`sm` accepts bash's arguments: `-c CMD`, `-lc`, `-o pipefail`, `--norc`,
`script.sh args`, commands on stdin, interactive.

## sm-ls and sm-add

```bash
sm-ls                    # NAME, CATEGORY, NOTE (never values); sm-ls github, -q, --json
sm-add JWT_SECRET --generate 48 --category MyApp --note "signing key"
some-command-printing-a-token | sm-add NEW_TOKEN --category X
```

`sm-add` only creates: it refuses an existing name (exit 3, `--if-missing` =
exit 0) and refuses a value given as an argument, so the value never shows up
in `ps`, shell history or an agent's transcript. It works with the client
token, so agents can use it; the GUI's Activity marks those as created "by an
agent (sm-add)". Replacing or deleting stays with the admin token (GUI/smctl).

## Agent skill

`skills/secret-manager/SKILL.md` teaches agents to find secrets with
`sm-ls`, create new ones with `sm-add`, run commands as `sm -c '… $NAME …'`,
and read anything that might contain a secret (.env, configs, logs, env dumps)
through `sm` so it is blocked before it reaches their context. The first time
an agent loads it in a conversation, it opens with a short line saying it uses
secret-manager and won't reveal or exfiltrate secret values.

Install by symlinking (edits and `git pull` take effect at once):

```bash
ln -s "$PWD/skills/secret-manager" ~/.claude/skills/secret-manager             # Claude Code
mkdir -p ~/.config/opencode/skills
ln -s "$PWD/skills/secret-manager" ~/.config/opencode/skills/secret-manager    # opencode
```

(opencode also reads `~/.claude/skills`; with both links it lists the skill once.)

For the announcement at the start of *every* conversation (not only when the
skill loads), append `skills/global-instructions.md` to the global instruction
files, which both agents always load:

```bash
cat skills/global-instructions.md >> ~/.claude/CLAUDE.md             # Claude Code
cat skills/global-instructions.md >> ~/.config/opencode/AGENTS.md    # opencode
```

Tested: asked to call an API "with our weather API key" (no mention of sm),
Claude Code and opencode both ran `sm -c 'curl -H "X-Api-Key: $WEATHER_API_KEY" …'`
and got the answer; the value never appeared in their output. Asked to
"look at .env and app.log" (both containing a stored secret), both read them
with `sm -c 'cat …'` instead of their built-in file reader and only ever saw
`[BLOCKED:NAME]`. If an agent
ignores the skill, plain commands simply don't have the secrets (fail closed).

## Using it as an agent's shell

Claude Code only accepts a shell whose name it recognises, so the link must be
called `bash`:

```bash
mkdir -p ~/.local/share/sm/bin
ln -sf /path/to/secret-manager/bin/sm.js ~/.local/share/sm/bin/bash
CLAUDE_CODE_SHELL=~/.local/share/sm/bin/bash claude    # or SHELL=...
```

Tested with Claude Code 2.1.330: the model saw `key=[BLOCKED:API_KEY]`, the
program got the 20-character value. Pointing `SHELL` at a link named `sm` was
ignored (Claude Code fell back to plain bash). opencode is not tested yet.

## Placeholders

- `$NAME`: secrets are exported under their own name if that variable is not
  already set (`SM_AUTO_ENV=0` turns this off).
- `{{secret:NAME}}` in a `-c` command is rewritten to `"${__SM_NAME}"` with the
  right quoting for where it appears (unquoted, `"..."`, `'...'`, `$'...'`), so
  values containing quotes, `$` or backslashes are safe and never end up in
  bash's argv. An unknown name stops the command before anything runs.
- Environment variables inherited by `sm` whose value contains a placeholder
  (e.g. `TOKEN='Bearer {{secret:API_KEY}}'`) are resolved.

## What gets caught

Raw values, hex (both cases), base64/base64url (also inside larger data, at any
byte offset), URL encoding, JSON escaping, on stdout and stderr. A secret split
across output chunks is caught if the pieces arrive within 150 ms.

```bash
npm test        # 28 tests: redactor, quoting rewrite, shell, server API
npm run demo    # leak matrix: 11/18 caught; the 7 misses are deliberate attacks
```

## What it does not stop

- Transformations: `rev`, spaced letters, xor, compression, arithmetic...
- One character per command, yes/no questions, exit codes.
- Writing the value to a file, git, or the network and reading it elsewhere.
- Pieces written more than 150 ms apart (the held prefix is then released).
- Same-user access: reading `.sm/secrets.json`, or `/proc/<pid>/environ` of
  a running command.

Protecting against those needs a boundary the agent can't cross (a broker or
proxy outside its sandbox, plus host/command allowlists).

## Prototype shortcuts

- Without `smctl login`, the store is a plain JSON file (0600) in `.sm/`.
- Any process with the client token can fetch all values (no per-secret scoping yet).
- Every secret is exported into every shell; there is no per-command scoping.
- Commands run under `-c` get pipes, not a terminal, so tools that check
  `isatty` turn off colours/prompts (as they would for any agent).
- Interactive mode: the terminal size is set at start only (no resize).
- Placeholders in heredoc bodies and in script files are not rewritten (use `$NAME`).
- Short secrets (< 8 chars) also redact unrelated text that contains them.
