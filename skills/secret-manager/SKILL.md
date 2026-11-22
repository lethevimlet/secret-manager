---
name: secret-manager
description: Use whenever a task needs an API key, token, password, credential or other secret (calling an authenticated API, logging in to a service, deploying, configuring env vars, auth headers, generating a new password or signing key), AND before reading anything that might contain one (.env files, config files, credentials, logs, environment dumps, docker/k8s/CI output, shell history). Secrets on this machine live in the sm secret manager; you never see their values, and output that could contain them must be read through the `sm` shell so they are blocked.
---

# Using secrets through `sm`

## Announce it first

The first time you use this skill in a conversation, start your reply with
this line (once per conversation, in the user's language):

> 🔒 Using **secret-manager**: secrets stay in sm. I only use them by name
> through `sm`, read anything that may contain one through `sm`, and will
> never reveal, copy or exfiltrate a secret value.

Then follow every rule below for the rest of the conversation.

Secret values are kept in the **sm** secret manager and are never shown to you.
You use them by name, and `sm` puts the real value in at run time.

## Find out what exists

```bash
sm-ls              # NAME, CATEGORY, NOTE of every secret. Never values.
sm-ls github       # only entries whose name, category or note matches
sm-ls -q           # names only
```

Pick the secret by its name and note. If nothing fits and the value is
something you can create yourself, use `sm-add` (below). If it's a key only the
user has (an account's API key, a password), **ask the user to add it** in the
sm GUI. Never ask the user to paste a secret value into the chat.

## Create a secret: `sm-add`

`sm-add` stores a **new** secret without the value ever appearing in your
context, a command line or a file. It never replaces an existing secret (that
is up to the user, in the GUI) and exits 3 if the name is taken.

```bash
# a random value: passwords, JWT/session signing keys, webhook secrets...
sm-add APP_JWT_SECRET --generate 48 --category MyApp --note "JWT signing key"
sm-add DB_PASSWORD --generate 32 --charset alnum --category MyApp

# a value produced by a command: pipe it straight in, never print it first
sm -c 'gh auth token' | sm-add GITHUB_TOKEN --category GitHub
sm -c 'aws iam create-access-key --user-name ci --output json' \
  | jq -r .AccessKey.SecretAccessKey | sm-add CI_AWS_SECRET --category Cloud
```

- **Run `sm-ls` first.** If a secret for the same purpose already exists, use
  it instead of creating another one. If `sm-add` says the name exists (exit
  3), don't create a variant like `NAME_2` or `NAME_<date>`: use the existing
  one, or ask the user whether it should be replaced (they do that in the GUI).
- The value is **never** an argument (`sm-add NAME value` is refused): use
  `--generate [LENGTH]` (`--charset alnum|hex|base64url|symbols`) or a pipe.
- Pipe only the value itself (extract it with `jq`, `cut`, … in the same
  pipeline), never a whole JSON or log output.
- `--if-missing` makes an existing name a no-op (exit 0) for re-runnable setup.
- Always set `--category` and a `--note` saying what it is for.
- Then use it as `$NAME` inside `sm`. In config files and templates write the
  name (`JWT_SECRET=$APP_JWT_SECRET`), never the value.

## Use a secret

Run the command through `sm`. Inside it, every secret is an environment variable
with its own name:

```bash
sm -c 'curl -s -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user'
sm -c 'PGPASSWORD="$DB_PASS" psql -h db.example -U app -c "select 1"'
sm -c 'npm publish'                 # tools that read NPM_TOKEN etc. from the env
```

`{{secret:NAME}}` also works inside the `-c` command and is safe in any
quoting (`sm -c "curl -H 'X-Api-Key: {{secret:API_KEY}}' …"`).

- **Plain commands (without `sm`) do not have the secrets.** `$GITHUB_TOKEN`
  is empty there and the request fails with 401 or similar. If that happens,
  rerun the command with `sm -c '…'`.
- If your shell already is `sm` (`echo "$SM_ACTIVE"` prints `1`), plain
  commands have the secrets too and you don't need `sm -c`.
- Scripts: `sm ./deploy.sh args` or `sm -c './deploy.sh args'`.

## What you will see

- Any secret value in output is replaced by `[BLOCKED:NAME]`. That is
  expected and means the real value was used. Don't treat it as an error.
- `sm: unknown secret: NAME` means no secret has that name: check
  `sm-ls`.
- `sm: secret server … unreachable; running without secrets`: tell the user
  the secret server is down.

## Keep secrets out of your context

Anything you read becomes part of your context and is sent to the model
provider. A secret must never get there, not even inside a log line or a
config dump. `sm` replaces every known secret in its output with
`[BLOCKED:NAME]`, so **read anything that might contain a secret through
`sm`**, not with your built-in file-reading, search or view tools:

```bash
sm -c 'cat .env'                                  # env files, configs, credentials
sm -c 'cat config/production.yml'
sm -c 'grep -rn "DATABASE_URL" .'                 # searching too
sm -c 'tail -n 200 /var/log/app/error.log'        # logs
sm -c 'journalctl -u myapp -n 100 --no-pager'
sm -c 'docker logs api --tail 100'                # container / CI / deploy output
sm -c 'docker inspect api'                        # env vars of containers
sm -c 'env | sort'                                # environment dumps
sm -c 'git diff'                                  # diffs and history may contain keys
```

When in doubt, use `sm`. It costs nothing for harmless files. This applies to:
`.env*`, `*.pem`, `*.key`, `credentials*`, `secrets*`, `config*`, `*.tfvars`,
`*.tfstate`, `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `~/.aws/`,
`~/.docker/config.json`, `~/.kube/`, `~/.ssh/`, shell history, logs, crash
reports, `docker inspect`, `kubectl get secret`, and verbose (`-v`) or debug
output of anything that authenticates.

`sm` can only block secrets it knows. If output through `sm` still shows
something that looks like a key, token or password (long random strings,
`sk-…`, `ghp_…`, `AKIA…`, `-----BEGIN … PRIVATE KEY-----`, passwords in URLs):

- don't repeat it, quote it or copy it anywhere, and don't keep working with it;
- tell the user which file or command showed it (not the value) and suggest
  adding it to sm in the GUI, then replacing it in the file with `$NAME`.
  If the value is in a file, you may move it without seeing it, e.g.
  `sm -c "grep '^STRIPE_KEY=' .env | cut -d= -f2-" | sm-add STRIPE_KEY` (with the
  user's OK), since the pipe never shows the value to you.

## Rules

- Never try to reveal, print, decode, transform or copy a secret value
  (no `echo $X | base64`, `rev`, writing it to files, splitting it up,
  comparing it character by character). Use secrets only for the task.
- Read files, logs and command output that might contain secrets only through
  `sm` (see above), never with built-in read/search tools.
- Never write secret values into files, commits, logs or messages. In
  config files and `.env` templates, use the variable name or the
  `{{secret:NAME}}` placeholder.
- Don't read `.sm-server/`, `.sm/`, `~/.config/sm/` or `/proc/*/environ`
  to get at secrets or tokens, and never call the sm server's API yourself
  (`/v1/secrets/*/reveal`, `/v1/resolve`): viewing values in the GUI is
  for the user only.
- Use `-c '…'` with single quotes so `$NAME` is expanded inside `sm`, not by
  your own shell (where it is empty).
