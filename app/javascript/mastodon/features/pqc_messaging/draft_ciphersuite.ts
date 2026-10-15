import { Chacha20Poly1305 } from '@hpke/chacha20poly1305';
import { CipherSuite, HkdfSha384 } from '@hpke/core';
import { XWing } from '@hpke/hybridkem-x-wing';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { nobleCryptoProvider } from 'ts-mls';
import type {
  CiphersuiteImpl,
  Hpke,
  PrivateKey,
  PublicKey,
  Signature,
} from 'ts-mls';

import { DRAFT_PQC_MLS_CIPHERSUITE_ID } from './cipher_suite_ids';

export { DRAFT_PQC_MLS_CIPHERSUITE_ID } from './cipher_suite_ids';

const toArrayBuffer = (value: Uint8Array): ArrayBuffer =>
  value.buffer.slice(
    value.byteOffset,
    value.byteOffset + value.byteLength,
  ) as ArrayBuffer;

const createDraftHpke = (): Hpke => {
  const aead = new Chacha20Poly1305();
  const suite = new CipherSuite({
    kem: new XWing(),
    kdf: new HkdfSha384(),
    aead,
  });
  const empty = new Uint8Array();

  return {
    async open(privateKey, kemOutput, ciphertext, info, aad) {
      const plaintext = await suite.open(
        {
          recipientKey: privateKey,
          enc: toArrayBuffer(kemOutput),
          info: toArrayBuffer(info),
        },
        toArrayBuffer(ciphertext),
        toArrayBuffer(aad ?? empty),
      );
      return new Uint8Array(plaintext);
    },
    async seal(publicKey, plaintext, info, aad) {
      const result = await suite.seal(
        { recipientPublicKey: publicKey, info: toArrayBuffer(info) },
        toArrayBuffer(plaintext),
        toArrayBuffer(aad ?? empty),
      );
      return { ct: new Uint8Array(result.ct), enc: new Uint8Array(result.enc) };
    },
    async exportSecret(publicKey, exporterContext, length, info) {
      const context = await suite.createSenderContext({
        recipientPublicKey: publicKey,
        info: toArrayBuffer(info),
      });
      return {
        enc: new Uint8Array(context.enc),
        secret: new Uint8Array(
          await context.export(toArrayBuffer(exporterContext), length),
        ),
      };
    },
    async importSecret(privateKey, exporterContext, kemOutput, length, info) {
      const context = await suite.createRecipientContext({
        recipientKey: privateKey,
        info: toArrayBuffer(info),
        enc: toArrayBuffer(kemOutput),
      });
      return new Uint8Array(
        await context.export(toArrayBuffer(exporterContext), length),
      );
    },
    async importPrivateKey(key) {
      return suite.kem.deserializePrivateKey(
        toArrayBuffer(key),
      ) as Promise<PrivateKey>;
    },
    async importPublicKey(key) {
      return suite.kem.deserializePublicKey(
        toArrayBuffer(key),
      ) as Promise<PublicKey>;
    },
    async exportPublicKey(key) {
      return new Uint8Array(await suite.kem.serializePublicKey(key));
    },
    async exportPrivateKey(key) {
      return new Uint8Array(await suite.kem.serializePrivateKey(key));
    },
    async encryptAead(key, nonce, aad, plaintext) {
      const context = aead.createEncryptionContext(toArrayBuffer(key));
      return new Uint8Array(
        await context.seal(
          toArrayBuffer(nonce),
          toArrayBuffer(plaintext),
          toArrayBuffer(aad ?? empty),
        ),
      );
    },
    async decryptAead(key, nonce, aad, ciphertext) {
      const context = aead.createEncryptionContext(toArrayBuffer(key));
      return new Uint8Array(
        await context.open(
          toArrayBuffer(nonce),
          toArrayBuffer(ciphertext),
          toArrayBuffer(aad ?? empty),
        ),
      );
    },
    async deriveKeyPair(ikm) {
      const keyPair = await suite.kem.deriveKeyPair(toArrayBuffer(ikm));
      return {
        privateKey: keyPair.privateKey as PrivateKey,
        publicKey: keyPair.publicKey as PublicKey,
      };
    },
    async generateKeyPair() {
      const keyPair = await suite.kem.generateKeyPair();
      return {
        privateKey: keyPair.privateKey as PrivateKey,
        publicKey: keyPair.publicKey as PublicKey,
      };
    },
    keyLength: aead.keySize,
    nonceLength: aead.nonceSize,
  };
};

const signature: Signature = {
  sign: (signKey, message) => Promise.resolve(ml_dsa44.sign(message, signKey)),
  verify: (publicKey, message, value) =>
    Promise.resolve(ml_dsa44.verify(value, message, publicKey)),
  keygen: () => {
    const keys = ml_dsa44.keygen(crypto.getRandomValues(new Uint8Array(32)));
    return Promise.resolve({
      signKey: keys.secretKey,
      publicKey: keys.publicKey,
    });
  },
};

export const createDraftPqcMlsCiphersuite =
  async (): Promise<CiphersuiteImpl> => {
    // Suite 0xf009 uses HKDF-SHA-512 internally despite its SHA-384 transcript
    // hash. Use the standardized P-384 suite as the source for HKDF-SHA-384,
    // then replace its HPKE, signature, and suite identifier below.
    const sha384 = await nobleCryptoProvider.getCiphersuiteImpl(0x0007);

    return {
      ...sha384,
      hpke: createDraftHpke(),
      signature,
      id: DRAFT_PQC_MLS_CIPHERSUITE_ID,
    };
  };
