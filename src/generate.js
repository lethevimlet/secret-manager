// Random secret values: crypto.randomBytes with rejection sampling (no modulo bias).
import crypto from 'node:crypto';

export const CHARSETS = {
  alnum: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
  hex: '0123456789abcdef',
  base64url: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
  symbols: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#%+-.:=?@^_~',
};
export const MIN_LENGTH = 8;
export const MAX_LENGTH = 4096;

export function generateValue(length = 12, charset = 'alnum') {
  const chars = CHARSETS[charset];
  if (!chars) throw Object.assign(new Error(`unknown charset ${charset} (${Object.keys(CHARSETS).join(', ')})`), { status: 400 });
  const len = Number(length);
  if (!Number.isInteger(len) || len < MIN_LENGTH || len > MAX_LENGTH) {
    throw Object.assign(new Error(`length must be a whole number from ${MIN_LENGTH} to ${MAX_LENGTH}`), { status: 400 });
  }
  const out = [];
  const limit = 256 - (256 % chars.length);
  while (out.length < len) {
    for (const b of crypto.randomBytes(len * 2)) {
      if (b < limit && out.length < len) out.push(chars[b % chars.length]);
    }
  }
  return out.join('');
}
