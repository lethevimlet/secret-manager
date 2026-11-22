// Streaming output redaction.
//
// Works on bytes (latin1 strings, 1 char = 1 byte) so multi-byte UTF-8 and
// binary output never break matching. Catches each secret in raw form and in
// common encodings. It is a safety net against ACCIDENTAL leaks only: any
// transformation not listed here (rev, char-by-char, xor, ...) gets through.
import { Transform } from 'node:stream';

export const MIN_VARIANT_LEN = 4;

const latin1 = (s) => Buffer.from(s, 'utf8').toString('latin1');

// Base64 of a value embedded at an unknown offset in a larger stream: encode
// with 0/1/2 bytes of leading padding and keep only the characters that depend
// on the secret's bytes alone.
function base64Cores(raw) {
  const cores = [];
  for (let off = 0; off < 3; off++) {
    const b64 = Buffer.concat([Buffer.alloc(off), raw]).toString('base64');
    const head = [0, 2, 3][off];
    const rem = (off + raw.length) % 3;
    const tail = [0, 3, 2][rem];
    const core = b64.slice(head, b64.length - tail);
    cores.push(core, core.replace(/\+/g, '-').replace(/\//g, '_'));
  }
  return cores;
}

export function variantsOf(value) {
  const raw = Buffer.from(value, 'utf8');
  const out = new Set([
    raw.toString('latin1'),
    raw.toString('hex'),
    raw.toString('hex').toUpperCase(),
    encodeURIComponent(value),
    encodeURIComponent(value).replace(/%20/g, '+'),
    latin1(JSON.stringify(value).slice(1, -1)),
    ...base64Cores(raw),
  ]);
  return [...out].filter((v) => v.length >= MIN_VARIANT_LEN);
}

export class Redactor {
  // secrets: { NAME: value }
  constructor(secrets) {
    this.patterns = [];
    for (const [name, value] of Object.entries(secrets)) {
      for (const v of variantsOf(value)) this.patterns.push({ text: v, name });
    }
    // Longest first so a raw secret wins over a shorter encoding inside it.
    this.patterns.sort((a, b) => b.text.length - a.text.length);
    this.maxLen = this.patterns.reduce((m, p) => Math.max(m, p.text.length), 0);
    this.counts = {};
  }

  // Redact complete matches in `s`. Returns { out, rest } where `rest` is the
  // tail that could be the beginning of a secret and must wait for more data.
  scan(s, final = false) {
    let out = '';
    let i = 0;
    for (;;) {
      let best = null;
      for (const p of this.patterns) {
        const at = s.indexOf(p.text, i);
        if (at !== -1 && (best === null || at < best.at)) best = { at, p };
      }
      if (!best) break;
      out += s.slice(i, best.at) + `[BLOCKED:${best.p.name}]`;
      this.counts[best.p.name] = (this.counts[best.p.name] || 0) + 1;
      i = best.at + best.p.text.length;
    }
    const tail = s.slice(i);
    const hold = final ? 0 : this.holdback(tail);
    return { out: out + tail.slice(0, tail.length - hold), rest: tail.slice(tail.length - hold) };
  }

  // Length of the longest suffix of `s` that is a proper prefix of a pattern.
  holdback(s) {
    for (let k = Math.min(this.maxLen - 1, s.length); k > 0; k--) {
      const suffix = s.slice(s.length - k);
      if (this.patterns.some((p) => p.text.startsWith(suffix))) return k;
    }
    return 0;
  }

  redactString(s) {
    return Buffer.from(this.scan(latin1(s), true).out, 'latin1').toString('utf8');
  }

  // Transform stream. Normal output passes through immediately; only a tail
  // that might be the start of a secret is held, and released after `idleMs`
  // of silence (so interactive prompts still show up). A secret written in two
  // pieces more than `idleMs` apart therefore leaks its first piece.
  stream({ idleMs = 150 } = {}) {
    let pending = '';
    let timer = null;
    const self = this;
    const t = new Transform({
      transform(chunk, _enc, cb) {
        clearTimeout(timer);
        const { out, rest } = self.scan(pending + chunk.toString('latin1'));
        pending = rest;
        if (out) this.push(Buffer.from(out, 'latin1'));
        if (pending) {
          timer = setTimeout(() => {
            const { out: o } = self.scan(pending, true);
            pending = '';
            t.push(Buffer.from(o, 'latin1'));
          }, idleMs);
        }
        cb();
      },
      flush(cb) {
        clearTimeout(timer);
        if (pending) this.push(Buffer.from(self.scan(pending, true).out, 'latin1'));
        pending = '';
        cb();
      },
    });
    return t;
  }
}
