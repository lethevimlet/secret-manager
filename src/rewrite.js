// Rewrite {{secret:NAME}} inside a bash command string into a reference to an
// environment variable (__SM_NAME) instead of pasting the value in. This keeps
// values out of bash's argv and makes quotes/$ in values safe, whatever quoting
// context the placeholder sits in:
//   unquoted         {{secret:X}}  ->  "${__SM_X}"
//   "double quotes"  {{secret:X}}  ->  ${__SM_X}
//   'single quotes'  {{secret:X}}  ->  '"${__SM_X}"'
//   $'ansi-c'        {{secret:X}}  ->  '"${__SM_X}"$'
// Not handled: heredoc bodies (treated as unquoted text).
import { PLACEHOLDER_RE } from './placeholders.js';

export const envName = (name) => `__SM_${name}`;

export function rewriteCommand(cmd, onName) {
  const ph = new RegExp(PLACEHOLDER_RE.source, 'y');
  let out = '';
  let state = 'normal'; // normal | single | double | ansi
  for (let i = 0; i < cmd.length; ) {
    ph.lastIndex = i;
    const m = ph.exec(cmd);
    if (m) {
      const ref = '${' + envName(m[1]) + '}';
      onName?.(m[1]);
      out += { normal: `"${ref}"`, double: ref, single: `'"${ref}"'`, ansi: `'"${ref}"$'` }[state];
      i += m[0].length;
      continue;
    }
    const c = cmd[i];
    if (c === '\\' && state !== 'single') {
      out += cmd.slice(i, i + 2);
      i += 2;
      continue;
    }
    if (state === 'normal') {
      if (c === "'") state = 'single';
      else if (c === '"') state = 'double';
      else if (c === '$' && cmd[i + 1] === "'") {
        out += "$'";
        i += 2;
        state = 'ansi';
        continue;
      }
    } else if ((state === 'single' || state === 'ansi') && c === "'") state = 'normal';
    else if (state === 'double' && c === '"') state = 'normal';
    out += c;
    i++;
  }
  return out;
}
