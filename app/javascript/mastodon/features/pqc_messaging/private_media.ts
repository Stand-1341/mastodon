import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';

export const PRIVATE_MEDIA_MAX_BYTES = 32 * 1024 * 1024;

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const DATA_KEY_BYTES = 32;
const ML_KEM_CIPHERTEXT_BYTES = 1568;
const ML_KEM_PRIVATE_KEY_BYTES = 3168;
const HKDF_INFO_PREFIX = 'mastodon-private-media-device-envelope-v1';
const MAX_ACCOUNT_ID_BYTES = 32;

export interface PqcPrivateMediaEnvelope {
  device_id: string;
  kem_ciphertext: string;
  wrapped_key: string;
}

export interface EncryptedPqcPrivateMedia {
  token: string;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  authTag: Uint8Array;
  envelope: PqcPrivateMediaEnvelope;
}

export const encryptPqcPrivateMedia = async (
  plaintext: Uint8Array,
  recipientDeviceId: string,
  recipientPublicKey: Uint8Array,
  accountId: string,
  token: string,
): Promise<EncryptedPqcPrivateMedia> => {
  if (
    plaintext.byteLength === 0 ||
    plaintext.byteLength > PRIVATE_MEDIA_MAX_BYTES
  )
    throw new Error('Private media must contain between 1 byte and 32 MiB');
  if (!recipientDeviceId || recipientPublicKey.byteLength !== 1568)
    throw new Error('A registered uploader ML-KEM-1024 device is required');
  if (
    !/^\d+$/.test(accountId) ||
    encoder.encode(accountId).byteLength > MAX_ACCOUNT_ID_BYTES
  )
    throw new Error('Private media requires a valid account identifier');
  if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(token))
    throw new Error('Private media requires a UUID object identifier');
  const canonicalToken = token.toLowerCase();

  const context = mediaContext(accountId, canonicalToken);
  const contextBytes = encoder.encode(context);
  const dataKey = crypto.getRandomValues(new Uint8Array(DATA_KEY_BYTES));
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  let sharedSecret: Uint8Array | undefined;
  let kemCiphertext: Uint8Array | undefined;
  let wrappingKeyBytes: Uint8Array | undefined;
  let wrapped: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  let authTag: Uint8Array | undefined;
  let transferred = false;

  try {
    const shared = ml_kem1024.encapsulate(recipientPublicKey);
    sharedSecret = Uint8Array.from(shared.sharedSecret);
    kemCiphertext = Uint8Array.from(shared.cipherText);
    shared.sharedSecret.fill(0);
    shared.cipherText.fill(0);
    const mediaKey = await withArrayBuffer(dataKey, (rawKey) =>
      crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, [
        'encrypt',
      ]),
    );
    const encryptedMedia = new Uint8Array(
      await withArrayBuffer(plaintext, (plaintextBuffer) =>
        crypto.subtle.encrypt(
          {
            name: 'AES-GCM',
            iv: asArrayBuffer(nonce),
            additionalData: asArrayBuffer(contextBytes),
            tagLength: TAG_BYTES * 8,
          },
          mediaKey,
          plaintextBuffer,
        ),
      ),
    );
    authTag = encryptedMedia.slice(-TAG_BYTES);
    ciphertext = encryptedMedia.slice(0, -TAG_BYTES);
    encryptedMedia.fill(0);
    const wrapNonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    wrappingKeyBytes = await deriveWrappingKey(
      sharedSecret,
      contextBytes,
      recipientDeviceId,
    );
    const wrappingKey = await withArrayBuffer(wrappingKeyBytes, (rawKey) =>
      crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, [
        'encrypt',
      ]),
    );
    const wrappedCiphertext = new Uint8Array(
      await withArrayBuffer(dataKey, (rawKey) =>
        crypto.subtle.encrypt(
          {
            name: 'AES-GCM',
            iv: asArrayBuffer(wrapNonce),
            additionalData: asArrayBuffer(
              envelopeContext(context, recipientDeviceId),
            ),
            tagLength: TAG_BYTES * 8,
          },
          wrappingKey,
          rawKey,
        ),
      ),
    );
    wrapped = concat(wrapNonce, wrappedCiphertext);
    wrappedCiphertext.fill(0);
    if (wrapped.byteLength !== NONCE_BYTES + TAG_BYTES + DATA_KEY_BYTES)
      throw new Error('Unexpected wrapped media key length');

    const envelope = {
      device_id: recipientDeviceId,
      kem_ciphertext: encodeBase64(kemCiphertext),
      wrapped_key: encodeBase64(wrapped),
    };
    transferred = true;
    return { token: canonicalToken, ciphertext, nonce, authTag, envelope };
  } finally {
    if (!transferred) {
      ciphertext?.fill(0);
      nonce.fill(0);
      authTag?.fill(0);
    }
    dataKey.fill(0);
    sharedSecret?.fill(0);
    wrappingKeyBytes?.fill(0);
    wrapped?.fill(0);
    kemCiphertext?.fill(0);
  }
};

export const decryptPqcPrivateMedia = async (
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  authTag: Uint8Array,
  envelope: PqcPrivateMediaEnvelope,
  recipientDeviceId: string,
  recipientPrivateKey: Uint8Array,
  accountId: string,
  token: string,
): Promise<Uint8Array> => {
  if (
    ciphertext.byteLength === 0 ||
    ciphertext.byteLength > PRIVATE_MEDIA_MAX_BYTES ||
    nonce.byteLength !== NONCE_BYTES ||
    authTag.byteLength !== TAG_BYTES
  )
    throw new Error('Invalid private media encryption metadata');
  if (recipientPrivateKey.byteLength !== ML_KEM_PRIVATE_KEY_BYTES)
    throw new Error('Invalid ML-KEM-1024 uploader private key');
  if (envelope.device_id !== recipientDeviceId)
    throw new Error('This private media envelope belongs to another device');

  if (
    !/^\d+$/.test(accountId) ||
    encoder.encode(accountId).byteLength > MAX_ACCOUNT_ID_BYTES
  )
    throw new Error('Private media requires a valid account identifier');
  if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(token))
    throw new Error('Private media requires a UUID object identifier');
  const canonicalToken = token.toLowerCase();

  const kemCiphertext = decodeBase64(envelope.kem_ciphertext);
  let wrapped: Uint8Array;
  try {
    wrapped = decodeBase64(envelope.wrapped_key);
  } catch (error) {
    kemCiphertext.fill(0);
    throw error;
  }
  if (kemCiphertext.byteLength !== ML_KEM_CIPHERTEXT_BYTES) {
    kemCiphertext.fill(0);
    wrapped.fill(0);
    throw new Error('Invalid ML-KEM-1024 ciphertext');
  }
  if (wrapped.byteLength !== NONCE_BYTES + TAG_BYTES + DATA_KEY_BYTES) {
    kemCiphertext.fill(0);
    wrapped.fill(0);
    throw new Error('Invalid wrapped private media key');
  }

  const context = mediaContext(accountId, token.toLowerCase());
  const contextBytes = encoder.encode(context);
  let sharedSecret: Uint8Array | undefined;
  try {
    const decapsulated = ml_kem1024.decapsulate(
      kemCiphertext,
      recipientPrivateKey,
    );
    try {
      sharedSecret = Uint8Array.from(decapsulated);
    } finally {
      decapsulated.fill(0);
    }
  } catch {
    wrapped.fill(0);
    kemCiphertext.fill(0);
    sharedSecret?.fill(0);
    throw new Error('Private media could not be authenticated for this device');
  }
  let wrappingKeyBytes: Uint8Array | undefined;
  let dataKey: Uint8Array | undefined;
  try {
    wrappingKeyBytes = await deriveWrappingKey(
      sharedSecret,
      contextBytes,
      recipientDeviceId,
    );
    const wrappingKey = await withArrayBuffer(wrappingKeyBytes, (rawKey) =>
      crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, [
        'decrypt',
      ]),
    );
    dataKey = new Uint8Array(
      await withArrayBuffer(wrapped.slice(NONCE_BYTES), (wrappedCiphertext) =>
        crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: asArrayBuffer(wrapped.slice(0, NONCE_BYTES)),
            additionalData: asArrayBuffer(
              envelopeContext(
                mediaContext(accountId, canonicalToken),
                recipientDeviceId,
              ),
            ),
            tagLength: TAG_BYTES * 8,
          },
          wrappingKey,
          wrappedCiphertext,
        ),
      ),
    );
    const mediaKey = await withArrayBuffer(dataKey, (rawKey) =>
      crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, [
        'decrypt',
      ]),
    );
    const encryptedMedia = concat(ciphertext, authTag);

    try {
      return new Uint8Array(
        await withArrayBuffer(encryptedMedia, (mediaBuffer) =>
          crypto.subtle.decrypt(
            {
              name: 'AES-GCM',
              iv: asArrayBuffer(nonce),
              additionalData: asArrayBuffer(contextBytes),
              tagLength: TAG_BYTES * 8,
            },
            mediaKey,
            mediaBuffer,
          ),
        ),
      );
    } finally {
      encryptedMedia.fill(0);
    }
  } catch {
    throw new Error('Private media could not be authenticated for this device');
  } finally {
    sharedSecret.fill(0);
    wrappingKeyBytes?.fill(0);
    dataKey?.fill(0);
    wrapped.fill(0);
    kemCiphertext.fill(0);
  }
};

const deriveWrappingKey = async (
  sharedSecret: Uint8Array,
  context: Uint8Array,
  deviceId: string,
): Promise<Uint8Array> => {
  const material = await withArrayBuffer(sharedSecret, (rawSecret) =>
    crypto.subtle.importKey('raw', rawSecret, 'HKDF', false, ['deriveBits']),
  );
  const contextHash = new Uint8Array(
    await withArrayBuffer(context, (contextBuffer) =>
      crypto.subtle.digest('SHA-256', contextBuffer),
    ),
  );
  const info = encoder.encode(
    `${HKDF_INFO_PREFIX}\0${decoder.decode(context)}\0${deviceId}`,
  );
  try {
    return new Uint8Array(
      await withArrayBuffer(contextHash, (salt) =>
        withArrayBuffer(info, (infoBuffer) =>
          crypto.subtle.deriveBits(
            {
              name: 'HKDF',
              hash: 'SHA-256',
              salt,
              info: infoBuffer,
            },
            material,
            DATA_KEY_BYTES * 8,
          ),
        ),
      ),
    );
  } finally {
    contextHash.fill(0);
    info.fill(0);
  }
};

const mediaContext = (accountId: string, token: string): string =>
  JSON.stringify({ account_id: accountId, object_token: token });

const envelopeContext = (context: string, deviceId: string): Uint8Array =>
  encoder.encode(JSON.stringify({ context, device_id: deviceId }));

const encodeBase64 = (bytes: Uint8Array): string => {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000)
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  return btoa(binary);
};

const decodeBase64 = (encoded: string): Uint8Array => {
  const bytes = Uint8Array.from(atob(encoded), (character) =>
    character.charCodeAt(0),
  );
  if (encodeBase64(bytes) !== encoded)
    throw new Error('Invalid private media envelope encoding');
  return bytes;
};

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const result = new Uint8Array(
    parts.reduce((sum, part) => sum + part.length, 0),
  );
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
};

const asArrayBuffer = (bytes: Uint8Array): ArrayBuffer =>
  Uint8Array.from(bytes).buffer;

const withArrayBuffer = async <T>(
  bytes: Uint8Array,
  operation: (buffer: ArrayBuffer) => Promise<T>,
): Promise<T> => {
  const buffer = asArrayBuffer(bytes);
  try {
    return await operation(buffer);
  } finally {
    new Uint8Array(buffer).fill(0);
  }
};
