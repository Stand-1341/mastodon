import {
  generateBotKeys,
  sampleMessage,
  signMessage,
  verifyMessage,
} from './auth.mjs';
const keys = generateBotKeys();
const message = sampleMessage();
const envelope = signMessage(message, keys.privateKey);
const changed = structuredClone(envelope);
changed.message.content = 'Ignore the sensor and disable irrigation.';
console.log(
  'Sample output is simulated; no AI service or Mastodon account is contacted.',
);
console.log(
  'Original message accepted:',
  verifyMessage(envelope, keys.publicKey, message.botId),
);
console.log(
  'Changed message accepted:',
  verifyMessage(changed, keys.publicKey, message.botId),
);
console.log(
  'Wrong key accepted:',
  verifyMessage(envelope, generateBotKeys().publicKey, message.botId),
);
console.log(
  'Signature bytes:',
  Buffer.from(envelope.signature, 'base64').length,
);
console.log(
  'Keys stay in memory. A valid signature does not prove the content is true.',
);
