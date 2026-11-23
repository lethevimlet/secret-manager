# rc file for interactive `sm` shells: load the user's normal setup, then mark
# the prompt so it's obvious secrets are injected and output is redacted.
[ -f /etc/bash.bashrc ] && . /etc/bash.bashrc
[ -f ~/.bashrc ] && . ~/.bashrc

# sm, or sm[work,org] when started with scopes (sm -s work,org). SM_SCOPES is
# set by sm itself from validated scope names, so it is safe inside PS1.
if [ -n "$SM_SCOPES" ]; then __sm_label="sm[$SM_SCOPES]"; else __sm_label=sm; fi
__sm_tag=${SM_PROMPT-$'\[\e[1;31m\]'"$__sm_label"$'\[\e[0m\] '}
unset __sm_label
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
