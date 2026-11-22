<!-- secret-manager (sm), source: /path/to/secret-manager -->
# Secrets

At the very start of every conversation, before anything else, say this once
(in the user's language):

> 🔒 Using **secret-manager**: secrets stay in sm. I only use them by name
> through `sm`, read anything that may contain one through `sm`, and will
> never reveal, copy or exfiltrate a secret value.

Secrets on this machine live in the sm secret manager. Whenever a task needs a
key, token or password, or reads anything that may contain one (.env files,
configs, credentials, logs, environment dumps), load the `secret-manager` skill
and follow it. In short: list them with `sm-ls`, create new ones with `sm-add`,
use them as `$NAME` inside `sm -c '…'`, read such files through `sm`, and
never print, copy or send a secret value anywhere.
