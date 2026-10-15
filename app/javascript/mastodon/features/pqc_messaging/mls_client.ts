import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
  clientStateDecoder,
  clientStateEncoder,
  createApplicationMessage,
  createCommit,
  createGroup,
  decode,
  defaultCredentialTypes,
  defaultProposalTypes,
  encode,
  generateKeyPackageWithKey,
  generateSignatureKeyPair,
  getCiphersuiteImpl,
  getGroupMembers,
  joinGroup,
  keyPackageDecoder,
  keyPackageEncoder,
  mlsMessageDecoder,
  mlsMessageEncoder,
  privateKeyPackageDecoder,
  privateKeyPackageEncoder,
  processMessage,
  protocolVersions,
  wireformats,
  zeroOutUint8Array,
} from 'ts-mls';
import type {
  ClientState,
  Credential,
  CiphersuiteImpl,
  MlsContext,
} from 'ts-mls';

import { DRAFT_PQC_MLS_CIPHERSUITE_ID } from './cipher_suite_ids';

export const PQC_MLS_CIPHERSUITE = 'MLS_256_XWING_AES256GCM_SHA512_MLDSA87';
export const LEGACY_PQC_MLS_CIPHERSUITE_ID = 0xf011;

export interface PqcDeviceKeyPackage {
  identity: string;
  fingerprint: string;
  deviceAuthPublicKey: Uint8Array;
  deviceAuthPrivateKey?: Uint8Array;
  publicPackage: Uint8Array;
  keyPackageMessage: Uint8Array;
  privatePackage: Uint8Array;
}

export type PqcMlsContext = MlsContext;

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const legacyCiphersuite = getCiphersuiteImpl(PQC_MLS_CIPHERSUITE);
let draftCiphersuite: Promise<CiphersuiteImpl> | undefined;

export const getPqcMlsCiphersuite = async (id: number) => {
  if (id === LEGACY_PQC_MLS_CIPHERSUITE_ID) return legacyCiphersuite;
  if (id === DRAFT_PQC_MLS_CIPHERSUITE_ID) {
    draftCiphersuite ??= import('./draft_ciphersuite').then(
      ({ createDraftPqcMlsCiphersuite }) => createDraftPqcMlsCiphersuite(),
    );
    return draftCiphersuite;
  }

  throw new Error(
    `Unsupported MLS cipher suite 0x${id.toString(16).padStart(4, '0')}`,
  );
};

export const getPqcDeviceCiphersuiteId = (
  keyPackage: PqcDeviceKeyPackage,
): number =>
  decodeRequired(keyPackageDecoder, keyPackage.publicPackage).cipherSuite;

export const createPqcMlsContext = async (
  trustedDevices: ReadonlyMap<string, string>,
  cipherSuiteId = LEGACY_PQC_MLS_CIPHERSUITE_ID,
): Promise<PqcMlsContext> => ({
  cipherSuite: await getPqcMlsCiphersuite(cipherSuiteId),
  authService: {
    validateCredential: async (credential, signaturePublicKey) =>
      validateCredential(trustedDevices, credential, signaturePublicKey),
    validateSuccessorCredential: (oldCredential, newCredential) => {
      const oldIdentity = credentialIdentity(oldCredential);
      const newIdentity = credentialIdentity(newCredential);

      return Promise.resolve(
        oldIdentity === newIdentity && trustedDevices.has(oldIdentity),
      );
    },
  },
});

export const generatePqcDeviceKeyPackage = async (
  actorUri: string,
  deviceId: string,
  cipherSuiteId = LEGACY_PQC_MLS_CIPHERSUITE_ID,
): Promise<PqcDeviceKeyPackage> => {
  const impl = await getPqcMlsCiphersuite(cipherSuiteId);
  const signatureKeyPair = await generateSignatureKeyPair(impl);
  const deviceAuthKeyPair = ml_dsa87.keygen();
  const deviceAuthPublicKey = Uint8Array.from(deviceAuthKeyPair.publicKey);
  const deviceAuthPrivateKey = Uint8Array.from(deviceAuthKeyPair.secretKey);
  zeroOutUint8Array(deviceAuthKeyPair.secretKey);
  const fingerprint = await fingerprintPublicKey(signatureKeyPair.publicKey);
  const identity = `${actorUri}\n${deviceId}\n${fingerprint}`;
  const credential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: encoder.encode(identity),
  };

  const result = await generateKeyPackageWithKey({
    credential,
    signatureKeyPair,
    cipherSuite: impl,
  });

  const encodedPublicPackage = encode(keyPackageEncoder, result.publicPackage);

  return {
    identity,
    fingerprint,
    deviceAuthPublicKey,
    deviceAuthPrivateKey,
    publicPackage: encodedPublicPackage,
    keyPackageMessage: encode(mlsMessageEncoder, {
      wireformat: wireformats.mls_key_package,
      keyPackage: result.publicPackage,
      version: protocolVersions.mls10,
    }),
    privatePackage: encode(privateKeyPackageEncoder, result.privatePackage),
  };
};

export const pqcDeviceAuthPublicKey = (
  keyPackage: PqcDeviceKeyPackage,
): Uint8Array => {
  const publicPackage = decodeRequired(
    keyPackageDecoder,
    keyPackage.publicPackage,
  );
  return Uint8Array.from(publicPackage.leafNode.signaturePublicKey);
};

export const rotatePqcDeviceKeyPackage = async (
  keyPackage: PqcDeviceKeyPackage,
): Promise<PqcDeviceKeyPackage> => {
  const publicPackage = decodeRequired(
    keyPackageDecoder,
    keyPackage.publicPackage,
  );
  const impl = await getPqcMlsCiphersuite(publicPackage.cipherSuite);
  // The MLS decoder may return Uint8Array views backed by its input. Rotation
  // must not wipe the claimed package: the client still needs its private HPKE
  // key to open the Welcome addressed to that package.
  const decodedPrivatePackage = decodeRequired(
    privateKeyPackageDecoder,
    Uint8Array.from(keyPackage.privatePackage),
  );
  const signatureKeyPair = {
    signKey: Uint8Array.from(decodedPrivatePackage.signaturePrivateKey),
    publicKey: Uint8Array.from(publicPackage.leafNode.signaturePublicKey),
  };

  try {
    const credential: Credential = {
      credentialType: defaultCredentialTypes.basic,
      identity: encoder.encode(keyPackage.identity),
    };
    const result = await generateKeyPackageWithKey({
      credential,
      signatureKeyPair,
      cipherSuite: impl,
    });
    const encodedPublicPackage = encode(
      keyPackageEncoder,
      result.publicPackage,
    );

    return {
      identity: keyPackage.identity,
      fingerprint: keyPackage.fingerprint,
      deviceAuthPublicKey: Uint8Array.from(keyPackage.deviceAuthPublicKey),
      deviceAuthPrivateKey: keyPackage.deviceAuthPrivateKey
        ? Uint8Array.from(keyPackage.deviceAuthPrivateKey)
        : undefined,
      publicPackage: encodedPublicPackage,
      keyPackageMessage: encode(mlsMessageEncoder, {
        wireformat: wireformats.mls_key_package,
        keyPackage: result.publicPackage,
        version: protocolVersions.mls10,
      }),
      privatePackage: encode(privateKeyPackageEncoder, result.privatePackage),
    };
  } finally {
    wipePrivateKeyPackage(decodedPrivatePackage);
    zeroOutUint8Array(signatureKeyPair.signKey);
    zeroOutUint8Array(signatureKeyPair.publicKey);
  }
};

export const signPqcDeviceRequest = async (
  keyPackage: PqcDeviceKeyPackage,
  method: string,
  path: string,
  timestamp: string,
  nonce: string,
  body: string,
): Promise<Uint8Array> => {
  const bodyDigest = await crypto.subtle.digest(
    'SHA-256',
    encoder.encode(body),
  );
  const bodyDigestHex = Array.from(new Uint8Array(bodyDigest), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('');
  const message = `Mastodon-PQC-Device-Auth-v1\n${method.toUpperCase()}\n${path}\n${timestamp}\n${nonce}\n${bodyDigestHex}`;

  if (keyPackage.deviceAuthPrivateKey)
    return ml_dsa87.sign(
      encoder.encode(message),
      keyPackage.deviceAuthPrivateKey,
    );

  // Legacy recovery records used the MLS signature key for request authentication.
  const privatePackage = decodeRequired(
    privateKeyPackageDecoder,
    keyPackage.privatePackage,
  );
  const signKey = Uint8Array.from(privatePackage.signaturePrivateKey);
  try {
    const publicPackage = decodeRequired(
      keyPackageDecoder,
      keyPackage.publicPackage,
    );
    const impl = await getPqcMlsCiphersuite(publicPackage.cipherSuite);
    return await impl.signature.sign(signKey, encoder.encode(message));
  } finally {
    zeroOutUint8Array(signKey);
    wipePrivateKeyPackage(privatePackage);
  }
};

export const trustPqcDevice = (
  trustedDevices: Map<string, string>,
  identity: string,
  confirmedFingerprint: string,
): void => {
  const identityFingerprint = identity.split('\n').at(-1);

  if (!identityFingerprint || identityFingerprint !== confirmedFingerprint) {
    throw new Error(
      'The confirmed fingerprint does not match the device identity',
    );
  }

  trustedDevices.set(identity, confirmedFingerprint);
};

export const createPqcGroup = async (
  context: PqcMlsContext,
  groupId: string,
  keyPackage: PqcDeviceKeyPackage,
): Promise<ClientState> => {
  const publicPackage = decodeRequired(
    keyPackageDecoder,
    keyPackage.publicPackage,
  );
  const decodedPrivatePackage = decodeRequired(
    privateKeyPackageDecoder,
    keyPackage.privatePackage,
  );
  const privatePackage = clonePrivateKeyPackage(decodedPrivatePackage);

  try {
    return await createGroup({
      context,
      groupId: encoder.encode(groupId),
      keyPackage: publicPackage,
      privateKeyPackage: privatePackage,
    });
  } finally {
    wipePrivateKeyPackage(decodedPrivatePackage);
    zeroOutUint8Array(keyPackage.privatePackage);
  }
};

export const addPqcGroupMember = async (
  context: PqcMlsContext,
  state: ClientState,
  encodedPublicPackage: Uint8Array,
): Promise<{ state: ClientState; commit: Uint8Array; welcome: Uint8Array }> => {
  const keyPackageMessage = decodeRequired(
    mlsMessageDecoder,
    encodedPublicPackage,
  );
  if (
    keyPackageMessage.wireformat !== wireformats.mls_key_package ||
    !('keyPackage' in keyPackageMessage)
  )
    throw new Error('Expected an MLS KeyPackage message');
  if (keyPackageMessage.keyPackage.cipherSuite !== context.cipherSuite.id) {
    throw new Error(
      'The invited device KeyPackage uses a different MLS cipher suite; register a device using the group suite',
    );
  }

  const commit = await createCommit({
    context,
    state,
    ratchetTreeExtension: true,
    extraProposals: [
      {
        proposalType: defaultProposalTypes.add,
        add: { keyPackage: keyPackageMessage.keyPackage },
      },
    ],
  });
  if (!commit.welcome)
    throw new Error('MLS did not create a Welcome message for the new member');
  commit.consumed.forEach(zeroOutUint8Array);

  return {
    state: commit.newState,
    commit: encode(mlsMessageEncoder, commit.commit),
    welcome: encode(mlsMessageEncoder, commit.welcome),
  };
};

export const removePqcGroupMembers = async (
  context: PqcMlsContext,
  state: ClientState,
  identities: string[],
): Promise<{ state: ClientState; commit: Uint8Array }> => {
  const identitiesToRemove = new Set(identities);
  if (
    identitiesToRemove.size === 0 ||
    identitiesToRemove.size !== identities.length
  )
    throw new Error('Choose one or more distinct group devices to remove');

  const leafIndices = state.ratchetTree.flatMap((node, nodeIndex) => {
    const candidate = node as unknown as
      | { nodeType: number; leaf: { credential: Credential } }
      | undefined;
    if (
      candidate?.nodeType !== 1 ||
      !identitiesToRemove.has(credentialIdentity(candidate.leaf.credential))
    )
      return [];
    return [nodeIndex / 2];
  });
  if (leafIndices.length !== identitiesToRemove.size)
    throw new Error('One or more selected devices are not in this MLS group');
  if (leafIndices.length >= getGroupMembers(state).length)
    throw new Error('An MLS group must retain at least one device');

  const result = await createCommit({
    context,
    state,
    extraProposals: leafIndices.map((removed) => ({
      proposalType: defaultProposalTypes.remove,
      remove: { removed },
    })),
  });
  result.consumed.forEach(zeroOutUint8Array);

  return {
    state: result.newState,
    commit: encode(mlsMessageEncoder, result.commit),
  };
};

export const createPqcCommit = async (
  context: PqcMlsContext,
  state: ClientState,
): Promise<{ state: ClientState; ciphertext: Uint8Array }> => {
  const result = await createCommit({ context, state });
  result.consumed.forEach(zeroOutUint8Array);

  return {
    state: result.newState,
    ciphertext: encode(mlsMessageEncoder, result.commit),
  };
};

export const joinPqcGroup = async (
  context: PqcMlsContext,
  welcomeBytes: Uint8Array,
  keyPackage: PqcDeviceKeyPackage,
  ratchetTree?: ClientState['ratchetTree'],
): Promise<ClientState> => {
  const welcomeMessage = decodeRequired(mlsMessageDecoder, welcomeBytes);
  const publicPackage = decodeRequired(
    keyPackageDecoder,
    keyPackage.publicPackage,
  );
  const decodedPrivatePackage = decodeRequired(
    privateKeyPackageDecoder,
    keyPackage.privatePackage,
  );
  const privatePackage = clonePrivateKeyPackage(decodedPrivatePackage);
  if (
    welcomeMessage.wireformat !== wireformats.mls_welcome ||
    !('welcome' in welcomeMessage)
  )
    throw new Error('Expected an MLS Welcome message');

  try {
    return await joinGroup({
      context,
      welcome: welcomeMessage.welcome,
      keyPackage: publicPackage,
      privateKeys: privatePackage,
      ratchetTree,
    });
  } finally {
    wipePrivateKeyPackage(decodedPrivatePackage);
    zeroOutUint8Array(keyPackage.privatePackage);
  }
};

export const createPqcApplicationMessage = async (
  context: PqcMlsContext,
  state: ClientState,
  plaintext: string,
): Promise<{ state: ClientState; ciphertext: Uint8Array }> => {
  const result = await createApplicationMessage({
    context,
    state,
    message: encoder.encode(plaintext),
  });
  result.consumed.forEach(zeroOutUint8Array);

  return {
    state: result.newState,
    ciphertext: encode(mlsMessageEncoder, result.message),
  };
};

export const processPqcApplicationMessage = async (
  context: PqcMlsContext,
  state: ClientState,
  ciphertext: Uint8Array,
): Promise<{ state: ClientState; plaintext: string }> => {
  const result = await processPqcMessage(context, state, ciphertext);
  if (result.kind !== 'application')
    throw new Error('Expected an MLS application message');

  return result;
};

export const processPqcMessage = async (
  context: PqcMlsContext,
  state: ClientState,
  ciphertext: Uint8Array,
): Promise<
  | { kind: 'application'; state: ClientState; plaintext: string }
  | { kind: 'state'; state: ClientState }
> => {
  const message = decodeRequired(mlsMessageDecoder, ciphertext);
  if (
    message.wireformat !== wireformats.mls_private_message &&
    message.wireformat !== wireformats.mls_public_message
  ) {
    throw new Error('Expected an MLS framed message');
  }
  const result = await processMessage({ context, state, message });
  result.consumed.forEach(zeroOutUint8Array);
  if (result.kind === 'newState')
    return { kind: 'state', state: result.newState };

  return {
    kind: 'application',
    state: result.newState,
    plaintext: decoder.decode(result.message),
  };
};

export const serializePqcGroupState = (state: ClientState): Uint8Array =>
  encode(clientStateEncoder, state);

export const deserializePqcGroupState = (
  serializedState: Uint8Array,
): ClientState => decodeRequired(clientStateDecoder, serializedState);

const PQC_STATE_FORMAT_VERSION = 1;
const PQC_STATE_SALT_BYTES = 16;
const PQC_STATE_NONCE_BYTES = 12;
const PQC_STATE_PBKDF2_ITERATIONS = 310_000;
const PQC_STATE_AUTHENTICATED_DATA = encoder.encode(
  'mastodon-pqc-mls-state-v1',
);
const PQC_RECOVERY_AUTHENTICATED_DATA = encoder.encode(
  'mastodon-pqc-local-recovery-v1',
);

export const sealPqcRecoveryData = async (
  data: Uint8Array,
  passphrase: string,
): Promise<Uint8Array> => {
  validateStatePassphrase(passphrase);
  const salt = crypto.getRandomValues(new Uint8Array(PQC_STATE_SALT_BYTES));
  const nonce = crypto.getRandomValues(new Uint8Array(PQC_STATE_NONCE_BYTES));
  const key = await derivePqcStateKey(passphrase, salt);
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: asArrayBuffer(nonce),
        additionalData: asArrayBuffer(PQC_RECOVERY_AUTHENTICATED_DATA),
      },
      key,
      asArrayBuffer(data),
    ),
  );

  return Uint8Array.from([
    PQC_STATE_FORMAT_VERSION,
    ...salt,
    ...nonce,
    ...encrypted,
  ]);
};

export const restorePqcRecoveryData = async (
  sealedData: Uint8Array,
  passphrase: string,
): Promise<Uint8Array> => {
  validateStatePassphrase(passphrase);
  const headerSize = 1 + PQC_STATE_SALT_BYTES + PQC_STATE_NONCE_BYTES;
  if (
    sealedData.byteLength <= headerSize ||
    sealedData[0] !== PQC_STATE_FORMAT_VERSION
  )
    throw new Error('Invalid encrypted PQC recovery data');

  const salt = sealedData.slice(1, 1 + PQC_STATE_SALT_BYTES);
  const nonceStart = 1 + PQC_STATE_SALT_BYTES;
  const nonce = sealedData.slice(
    nonceStart,
    nonceStart + PQC_STATE_NONCE_BYTES,
  );
  const ciphertext = sealedData.slice(headerSize);
  const key = await derivePqcStateKey(passphrase, salt);
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: asArrayBuffer(nonce),
          additionalData: asArrayBuffer(PQC_RECOVERY_AUTHENTICATED_DATA),
        },
        key,
        asArrayBuffer(ciphertext),
      ),
    );
  } catch {
    throw new Error(
      'Unable to decrypt local PQC recovery data with this passphrase',
    );
  }
};

export const sealVerifiedPqcRecoveryData = async (
  plaintext: Uint8Array,
  replacementPassphrase: string,
): Promise<Uint8Array> => {
  const replacement = await sealPqcRecoveryData(
    plaintext,
    replacementPassphrase,
  );
  const verification = await restorePqcRecoveryData(
    replacement,
    replacementPassphrase,
  );
  try {
    if (
      verification.byteLength !== plaintext.byteLength ||
      verification.some((byte, index) => byte !== plaintext[index])
    ) {
      throw new Error('The updated recovery record could not be verified');
    }
  } finally {
    verification.fill(0);
  }

  return replacement;
};

export const sealPqcGroupState = async (
  state: ClientState,
  passphrase: string,
): Promise<Uint8Array> => {
  validateStatePassphrase(passphrase);
  const salt = crypto.getRandomValues(new Uint8Array(PQC_STATE_SALT_BYTES));
  const nonce = crypto.getRandomValues(new Uint8Array(PQC_STATE_NONCE_BYTES));
  const key = await derivePqcStateKey(passphrase, salt);
  const plaintext = encode(clientStateEncoder, state);
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: asArrayBuffer(nonce),
        additionalData: asArrayBuffer(PQC_STATE_AUTHENTICATED_DATA),
      },
      key,
      asArrayBuffer(plaintext),
    ),
  );

  return Uint8Array.from([
    PQC_STATE_FORMAT_VERSION,
    ...salt,
    ...nonce,
    ...encrypted,
  ]);
};

export const restorePqcGroupState = async (
  sealedState: Uint8Array,
  passphrase: string,
): Promise<ClientState> => {
  validateStatePassphrase(passphrase);
  const headerSize = 1 + PQC_STATE_SALT_BYTES + PQC_STATE_NONCE_BYTES;
  if (
    sealedState.byteLength <= headerSize ||
    sealedState[0] !== PQC_STATE_FORMAT_VERSION
  )
    throw new Error('Invalid encrypted MLS state');

  const salt = sealedState.slice(1, 1 + PQC_STATE_SALT_BYTES);
  const nonceStart = 1 + PQC_STATE_SALT_BYTES;
  const nonce = sealedState.slice(
    nonceStart,
    nonceStart + PQC_STATE_NONCE_BYTES,
  );
  const ciphertext = sealedState.slice(headerSize);
  const key = await derivePqcStateKey(passphrase, salt);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: asArrayBuffer(nonce),
        additionalData: asArrayBuffer(PQC_STATE_AUTHENTICATED_DATA),
      },
      key,
      asArrayBuffer(ciphertext),
    );
  } catch {
    throw new Error('Unable to decrypt MLS state with this passphrase');
  }

  return decodeRequired(clientStateDecoder, new Uint8Array(plaintext));
};

export const fingerprintPublicKey = async (
  publicKey: Uint8Array,
): Promise<string> => {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    Uint8Array.from(publicKey),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('');
};

const validateCredential = async (
  trustedDevices: ReadonlyMap<string, string>,
  credential: Credential,
  signaturePublicKey: Uint8Array,
): Promise<boolean> => {
  let identity: string;
  try {
    identity = credentialIdentity(credential);
  } catch {
    return false;
  }

  const expectedFingerprint = trustedDevices.get(identity);
  if (
    !expectedFingerprint ||
    expectedFingerprint !== (await fingerprintPublicKey(signaturePublicKey))
  ) {
    return false;
  }

  return true;
};

const credentialIdentity = (credential: Credential): string => {
  if (
    credential.credentialType !== defaultCredentialTypes.basic ||
    !('identity' in credential)
  )
    throw new Error('Unsupported MLS credential type');

  return decoder.decode(credential.identity);
};

const decodeRequired = <T>(
  codec: Parameters<typeof decode<T>>[0],
  bytes: Uint8Array,
): T => {
  const decoded = decode(codec, bytes);
  if (decoded === undefined) throw new Error('Invalid MLS encoding');

  return decoded;
};

const clonePrivateKeyPackage = (privatePackage: {
  initPrivateKey: Uint8Array;
  hpkePrivateKey: Uint8Array;
  signaturePrivateKey: Uint8Array;
}) => ({
  initPrivateKey: Uint8Array.from(privatePackage.initPrivateKey),
  hpkePrivateKey: Uint8Array.from(privatePackage.hpkePrivateKey),
  signaturePrivateKey: Uint8Array.from(privatePackage.signaturePrivateKey),
});

const wipePrivateKeyPackage = (privatePackage: {
  initPrivateKey: Uint8Array;
  hpkePrivateKey: Uint8Array;
  signaturePrivateKey: Uint8Array;
}): void => {
  zeroOutUint8Array(privatePackage.initPrivateKey);
  zeroOutUint8Array(privatePackage.hpkePrivateKey);
  zeroOutUint8Array(privatePackage.signaturePrivateKey);
};

const validateStatePassphrase = (passphrase: string): void => {
  if (passphrase.length < 12)
    throw new Error(
      'MLS state passphrases must contain at least 12 characters',
    );
};

const derivePqcStateKey = async (
  passphrase: string,
  salt: Uint8Array,
): Promise<CryptoKey> => {
  const material = await crypto.subtle.importKey(
    'raw',
    asArrayBuffer(encoder.encode(passphrase)),
    'PBKDF2',
    false,
    ['deriveKey'],
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: asArrayBuffer(salt),
      iterations: PQC_STATE_PBKDF2_ITERATIONS,
    },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
};

const asArrayBuffer = (bytes: Uint8Array): ArrayBuffer =>
  Uint8Array.from(bytes).buffer;
