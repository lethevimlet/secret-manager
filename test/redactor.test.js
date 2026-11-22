import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { Redactor, variantsOf } from '../src/redactor.js';

const SECRETS = { API_KEY: 'sk-test-abcdef123456', DB_PASS: 'p@ss"w0rd/x+y z' };

async function streamThrough(chunks, opts) {
  const r = new Redactor(SECRETS);
  const out = [];
  await new Promise((resolve) => {
    Readable.from(chunks.map((c) => Buffer.from(c))).pipe(r.stream(opts)).on('data', (d) => out.push(d)).on('end', resolve);
  });
  return Buffer.concat(out).toString('utf8');
}

test('raw value is redacted', () => {
  const r = new Redactor(SECRETS);
  assert.equal(r.redactString('key=sk-test-abcdef123456!'), 'key=[BLOCKED:API_KEY]!');
});

test('encodings are redacted', () => {
  const r = new Redactor(SECRETS);
  const v = SECRETS.DB_PASS;
  for (const enc of [
    Buffer.from(v).toString('hex'),
    Buffer.from(v).toString('hex').toUpperCase(),
    encodeURIComponent(v),
    JSON.stringify(v),
    Buffer.from(v).toString('base64'),
    Buffer.from(v).toString('base64url'),
  ]) {
    assert.ok(!r.redactString(`x ${enc} y`).includes(enc), `not redacted: ${enc}`);
  }
});

test('base64 of the secret inside larger data is redacted at every offset', () => {
  const r = new Redactor(SECRETS);
  for (const prefix of ['', 'u', 'us', 'user:', 'Authorization: Bearer ']) {
    const b64 = Buffer.from(prefix + SECRETS.API_KEY + '\n').toString('base64');
    const out = r.redactString(b64);
    assert.match(out, /\[BLOCKED:API_KEY\]/, `prefix ${JSON.stringify(prefix)}`);
  }
});

test('secret split across chunks at every position is redacted', async () => {
  const text = `before ${SECRETS.API_KEY} after\n`;
  for (let i = 1; i < text.length; i++) {
    const out = await streamThrough([text.slice(0, i), text.slice(i)]);
    assert.equal(out, 'before [BLOCKED:API_KEY] after\n', `split at ${i}`);
  }
});

test('unrelated output is passed through unchanged, including UTF-8', async () => {
  const text = 'héllo wörld ✓ 日本語\n'.repeat(50);
  assert.equal(await streamThrough([text.slice(0, 7), text.slice(7)]), text);
});

test('idle timeout releases a held partial match (known limit)', async () => {
  // Prefix of the secret, then a long pause: the prefix is released.
  const out = await new Promise((resolve) => {
    const r = new Redactor(SECRETS);
    const s = r.stream({ idleMs: 20 });
    const got = [];
    s.on('data', (d) => got.push(d)).on('end', () => resolve(Buffer.concat(got).toString()));
    s.write('sk-test-');
    setTimeout(() => { s.write('abcdef123456\n'); s.end(); }, 60);
  });
  assert.equal(out, 'sk-test-abcdef123456\n'); // leaked: documented limitation
});

test('very short values produce no encoded variants shorter than 4 chars', () => {
  assert.ok(variantsOf('ab').every((v) => v.length >= 4));
});
