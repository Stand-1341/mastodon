import { generateKeyPairSync, sign, verify } from 'node:crypto';

export const ALGORITHM = 'ml-dsa-87';
const DOMAIN = 'Mastodon-Bot-Auth-Demo-v1\n';
// Fixed field order is this demo's wire format, not general JSON canonicalization.
export function signingBytes(message) {
  const fields = ['botId', 'messageId', 'createdAt', 'content'];
  if (
    !message ||
    Object.keys(message).length !== fields.length ||
    fields.some((k) => typeof message[k] !== 'string' || !message[k].length)
  ) {
    throw new TypeError('Expected exactly four nonempty string fields');
  }
  if (!Number.isFinite(Date.parse(message.createdAt)))
    throw new TypeError('Invalid timestamp');
  return Buffer.from(
    DOMAIN + JSON.stringify(fields.map((k) => message[k])),
    'utf8',
  );
}
export function generateBotKeys() {
  return generateKeyPairSync(ALGORITHM);
}
export function signMessage(message, privateKey) {
  if (privateKey.asymmetricKeyType !== ALGORITHM)
    throw new TypeError('ML-DSA-87 key required');
  return {
    algorithm: ALGORITHM,
    message: { ...message },
    signature: sign(null, signingBytes(message), privateKey).toString('base64'),
  };
}
// publicKey is provided by the verifier's trusted registry, never by the envelope.
export function verifyMessage(envelope, publicKey, expectedBotId) {
  try {
    if (
      publicKey.asymmetricKeyType !== ALGORITHM ||
      envelope.algorithm !== ALGORITHM ||
      envelope.message.botId !== expectedBotId ||
      typeof envelope.signature !== 'string'
    )
      return false;
    const signature = Buffer.from(envelope.signature, 'base64');
    if (
      signature.length !== 4627 ||
      signature.toString('base64') !== envelope.signature
    )
      return false;
    return verify(null, signingBytes(envelope.message), publicKey, signature);
  } catch {
    return false;
  }
}
export function sampleMessage() {
  return {
    botId: 'research-bot@demo.invalid',
    messageId: 'sample-001',
    createdAt: '2026-11-08T12:00:00.000Z',
    content:
      'Simulated AI bot output: Soil moisture is low. Please review irrigation needs.',
  };
}
