import assert from 'node:assert/strict';
import test from 'node:test';

import {
  generateBotKeys,
  sampleMessage,
  signMessage,
  verifyMessage,
} from './auth.mjs';
const keys = generateBotKeys();
const message = sampleMessage();
const envelope = signMessage(message, keys.privateKey);
const accepted = (e) => verifyMessage(e, keys.publicKey, message.botId);
test('original accepted', () => assert.equal(accepted(envelope), true));
for (const field of ['botId', 'messageId', 'createdAt', 'content']) {
  test(`changed ${field} rejected`, () => {
    const e = structuredClone(envelope);
    e.message[field] =
      field === 'createdAt' ? '2026-11-09T12:00:00.000Z' : 'changed';
    assert.equal(accepted(e), false);
  });
}
test('wrong trusted key rejected', () =>
  assert.equal(
    verifyMessage(envelope, generateBotKeys().publicKey, message.botId),
    false,
  ));
test('wrong expected identity rejected', () =>
  assert.equal(verifyMessage(envelope, keys.publicKey, 'imposter'), false));
test('signature corruption rejected', () => {
  const e = structuredClone(envelope);
  const b = Buffer.from(e.signature, 'base64');
  b[0] ^= 1;
  e.signature = b.toString('base64');
  assert.equal(accepted(e), false);
});
test('malformed and missing signatures rejected', () => {
  for (const s of ['', null, '!!!', envelope.signature.slice(1)])
    assert.equal(accepted({ ...envelope, signature: s }), false);
  assert.equal(accepted(null), false);
});
test('algorithm substitution rejected', () =>
  assert.equal(accepted({ ...envelope, algorithm: 'rsa' }), false));
test('unknown field rejected', () =>
  assert.equal(
    accepted({ ...envelope, message: { ...message, extra: 'unsigned?' } }),
    false,
  ));
test('field order does not change verification', () => {
  const e = structuredClone(envelope);
  e.message = Object.fromEntries(Object.entries(message).reverse());
  assert.equal(accepted(e), true);
});
test('Unicode round trip accepted; modifications rejected', () => {
  const m = { ...message, content: 'Mhoro 🌱 — soil moisture 25%' };
  const e = signMessage(m, keys.privateKey);
  assert.equal(accepted(e), true);
  e.message.content += '!';
  assert.equal(accepted(e), false);
});
test('signature verification alone allows replay (documented boundary)', () => {
  assert.equal(accepted(envelope), true);
  assert.equal(accepted(envelope), true);
});
