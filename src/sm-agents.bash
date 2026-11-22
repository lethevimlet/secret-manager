# Loaded into every sm shell (interactive via sm-rc.bash, non-interactive via
# BASH_ENV). AI agents must never inherit the secrets: their tool output goes
# to the model through the agent itself, not through sm's blocking. So these
# commands start the agent with every secret variable removed; the agent then
# uses `sm -c '…'` for single commands, as the secret-manager skill says.
if [ -n "$__SM_USER_BASH_ENV" ] && [ -f "$__SM_USER_BASH_ENV" ]; then . "$__SM_USER_BASH_ENV"; fi

__sm_agent() {
  local cmd=$1; shift
  local strip=(-u SM_ACTIVE -u __SM_SECRET_VARS -u __SM_USER_BASH_ENV -u BASH_ENV)
  local v
  for v in $__SM_SECRET_VARS; do strip+=(-u "$v"); done
  printf '\e[1;31msm:\e[0m starting %s without secrets (agents use `sm -c` per command, never run inside sm)\n' "$cmd" >&2
  if [ -n "$__SM_USER_BASH_ENV" ]; then
    command env "${strip[@]}" BASH_ENV="$__SM_USER_BASH_ENV" "$cmd" "$@"
  else
    command env "${strip[@]}" "$cmd" "$@"
  fi
}
# Aliases (e.g. clauderoot='claude …') expand to one of these names, so they're
# covered without wrapping the alias itself (that would be a syntax error).
for __sm_a in claude opencode codex aider gemini cursor-agent; do
  alias "$__sm_a" >/dev/null 2>&1 && continue
  eval "$__sm_a() { __sm_agent $__sm_a \"\$@\"; }"
done
unset __sm_a
