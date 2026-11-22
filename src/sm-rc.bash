# rc file for interactive `sm` shells: load the user's normal setup, then mark
# the prompt so it's obvious secrets are injected and output is redacted.
[ -f /etc/bash.bashrc ] && . /etc/bash.bashrc
[ -f ~/.bashrc ] && . ~/.bashrc

__sm_tag=${SM_PROMPT-$'\[\e[1;31m\]sm\[\e[0m\] '}
__sm_prompt() {
  case "$PS1" in
    "$__sm_tag"*) ;;
    *) PS1="$__sm_tag$PS1" ;;
  esac
}
# Runs before every prompt, after anything that rebuilds PS1 (starship etc.).
if [ -n "$__sm_tag" ]; then
  if [[ "$(declare -p PROMPT_COMMAND 2>/dev/null)" == "declare -a"* ]]; then
    PROMPT_COMMAND+=(__sm_prompt)
  else
    PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND$'\n'}__sm_prompt"
  fi
  __sm_prompt
fi

# Agents started from this shell get no secrets.
. "${BASH_SOURCE[0]%/*}/sm-agents.bash"
