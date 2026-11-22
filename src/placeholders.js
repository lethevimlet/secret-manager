// {{secret:NAME}} placeholders: what the agent sees and writes instead of values.
export const PLACEHOLDER_RE = /\{\{secret:([A-Za-z_][A-Za-z0-9_]*)\}\}/g;

export function placeholder(name) {
  return `{{secret:${name}}}`;
}

export function findNames(text) {
  return [...String(text).matchAll(PLACEHOLDER_RE)].map((m) => m[1]);
}

// Replace placeholders in `text` with values. Throws on unknown names so a
// typo never silently sends the literal placeholder somewhere.
export function substitute(text, secrets, used) {
  return String(text).replace(PLACEHOLDER_RE, (_, name) => {
    if (!(name in secrets)) throw new Error(`unknown secret: ${name}`);
    used?.add(name);
    return secrets[name];
  });
}
